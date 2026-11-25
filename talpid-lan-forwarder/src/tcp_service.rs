//! Optional in-process stream service above the existing TCP endpoint. This
//! interface carries bytes, never IP routing or physical socket authority.
use crate::{Flow, ReceiveScope, Refused};
use std::{
    io,
    sync::Arc,
    task::{Context, Poll},
};
use talpid_types::relay_flow::RelayBufferAllocator;

pub trait TcpService: Send + Sync {
    fn open(
        &self,
        flow: Flow,
        scope: &ReceiveScope,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<Box<dyn TcpChannel>, Refused>;
}

/// Nonblocking operations have exactly the same ownership as the endpoint's
/// rings. Readiness must not consume bytes, and shutdown closes only writes.
pub trait TcpChannel: Send {
    #[cfg(test)]
    fn network(&self) -> Option<&tokio::net::TcpStream> {
        None
    }
    fn current(&self) -> bool {
        true
    }
    /// Bytes remaining in the endpoint's transmit ring, including unacked data.
    fn queued_output(&mut self, _bytes: usize) {}
    fn try_read(&mut self, bytes: &mut [u8]) -> io::Result<usize>;
    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize>;
    fn shutdown(&mut self) -> io::Result<()>;
    fn abort(&mut self);
    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl TcpChannel for tokio::net::TcpStream {
    #[cfg(test)]
    fn network(&self) -> Option<&tokio::net::TcpStream> {
        Some(self)
    }
    fn try_read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        tokio::net::TcpStream::try_read(self, bytes)
    }
    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        tokio::net::TcpStream::try_write(self, bytes)
    }
    fn shutdown(&mut self) -> io::Result<()> {
        socket2::SockRef::from(&*self).shutdown(std::net::Shutdown::Write)
    }
    fn abort(&mut self) {
        let _ = socket2::SockRef::from(&*self).set_linger(Some(std::time::Duration::ZERO));
    }
    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::net::TcpStream::poll_read_ready(self, cx)
    }
    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::net::TcpStream::poll_write_ready(self, cx)
    }
}

/// A bounded, byte-credited in-memory stream with non-consuming readiness.
/// The async peer is used by protocol codecs; it cannot see endpoint internals.
pub struct ServiceStream {
    input: Arc<std::sync::Mutex<Ring>>,
    output: Arc<std::sync::Mutex<Ring>>,
    _storage: Arc<dyn talpid_types::relay_flow::RelayBufferReservation>,
}
struct Ring {
    bytes: std::collections::VecDeque<u8>,
    capacity: usize,
    closed: bool,
    reader: Option<std::task::Waker>,
    writer: Option<std::task::Waker>,
}

impl ServiceStream {
    pub fn pair(
        buffers: &dyn RelayBufferAllocator,
        capacity: usize,
    ) -> Result<(Self, Self), Refused> {
        if capacity == 0 {
            return Err(Refused::Full);
        }
        let bytes = capacity
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(2 * size_of::<Ring>() + 2 * size_of::<Self>() + 1024)
            })
            .ok_or(Refused::Full)?;
        let storage = buffers.try_reserve(bytes).map_err(|_| Refused::Full)?;
        let ring = || {
            Arc::new(std::sync::Mutex::new(Ring {
                bytes: std::collections::VecDeque::with_capacity(capacity),
                capacity,
                closed: false,
                reader: None,
                writer: None,
            }))
        };
        let input = ring();
        let output = ring();
        Ok((
            Self {
                input: input.clone(),
                output: output.clone(),
                _storage: storage.clone(),
            },
            Self {
                input: output,
                output: input,
                _storage: storage,
            },
        ))
    }
}

impl TcpChannel for ServiceStream {
    fn try_read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut ring = self.input.lock().unwrap();
        let n = bytes.len().min(ring.bytes.len());
        if n == 0 && !ring.closed && !bytes.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        for byte in &mut bytes[..n] {
            *byte = ring.bytes.pop_front().unwrap();
        }
        if let Some(waker) = ring.writer.take() {
            waker.wake();
        }
        Ok(n)
    }
    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut ring = self.output.lock().unwrap();
        if ring.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let n = bytes.len().min(ring.capacity - ring.bytes.len());
        if n == 0 && !bytes.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        ring.bytes.extend(&bytes[..n]);
        if let Some(waker) = ring.reader.take() {
            waker.wake();
        }
        Ok(n)
    }
    fn shutdown(&mut self) -> io::Result<()> {
        let mut ring = self.output.lock().unwrap();
        ring.closed = true;
        if let Some(waker) = ring.reader.take() {
            waker.wake();
        }
        Ok(())
    }
    fn abort(&mut self) {
        let _ = self.shutdown();
    }
    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut ring = self.input.lock().unwrap();
        if !ring.bytes.is_empty() || ring.closed {
            Poll::Ready(Ok(()))
        } else {
            ring.reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut ring = self.output.lock().unwrap();
        if ring.bytes.len() < ring.capacity || ring.closed {
            Poll::Ready(Ok(()))
        } else {
            ring.writer = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for ServiceStream {
    fn drop(&mut self) {
        for ring in [&self.input, &self.output] {
            let mut ring = ring.lock().unwrap();
            ring.closed = true;
            if let Some(waker) = ring.reader.take() {
                waker.wake();
            }
            if let Some(waker) = ring.writer.take() {
                waker.wake();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talpid_netstack::buffer_budget::BufferBudget;

    #[test]
    fn tcp_service_stream_backpressure_half_close_and_exact_refund() {
        let budget = BufferBudget::new(1024 * 1024);
        let (mut left, mut right) = ServiceStream::pair(&budget, 3).unwrap();
        assert_eq!(left.try_write(b"abcdef").unwrap(), 3);
        assert_eq!(
            left.try_write(b"d").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(left.poll_write_ready(&mut cx).is_pending());
        assert!(right.poll_read_ready(&mut cx).is_ready());
        let mut bytes = [0; 2];
        assert_eq!(right.try_read(&mut bytes).unwrap(), 2);
        assert_eq!(&bytes, b"ab");
        assert!(left.poll_write_ready(&mut cx).is_ready());
        left.shutdown().unwrap();
        assert_eq!(right.try_read(&mut bytes).unwrap(), 1);
        assert_eq!(bytes[0], b'c');
        assert_eq!(right.try_read(&mut bytes).unwrap(), 0);
        assert_eq!(right.try_write(b"ok").unwrap(), 2);
        assert_eq!(left.try_read(&mut bytes).unwrap(), 2);
        assert_eq!(&bytes, b"ok");
        drop(left);
        assert_eq!(
            right.try_write(b"x").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        drop(right);
        assert!(budget.try_reserve(1024 * 1024).is_ok());
    }

    #[test]
    fn tcp_service_stream_empty_read_and_partial_drain_on_peer_drop() {
        let budget = BufferBudget::new(1024 * 1024);
        let (mut left, mut right) = ServiceStream::pair(&budget, 3).unwrap();
        assert_eq!(left.try_read(&mut []).unwrap(), 0);
        assert_eq!(left.try_write(b"abc").unwrap(), 3);
        drop(left);
        let mut bytes = [0; 4];
        assert_eq!(right.try_read(&mut bytes).unwrap(), 3);
        assert_eq!(&bytes[..3], b"abc");
        assert_eq!(right.try_read(&mut bytes).unwrap(), 0);
    }
}
