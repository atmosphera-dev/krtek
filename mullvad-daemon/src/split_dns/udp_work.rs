//! Capture-owned Home work. No task, TUN descriptor or Ordinary capability is
//! created here. The sole frontend polls this owner and supplies checked writes.
//! Still inactive until full/Partial capture integration is complete.

use std::{
    collections::LinkedList,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use talpid_lan_forwarder::packet_receiver::{CompletedDatagram, IpError, PacketReceiver};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayBufferAllocator, RelayBufferReservation, RelayCapture, RelaySink,
};

use super::{
    home_path::HomeDnsPath,
    transport::ExchangeError,
    udp::{HomeUdpOutput, HomeUdpReply, UdpQuery},
};

type Answer = Pin<Box<dyn Future<Output = Result<HomeUdpReply, ExchangeError>> + Send>>;

struct Pending {
    input: CompletedDatagram,
    answer: Answer,
    result: Option<Result<HomeUdpReply, ExchangeError>>,
    charge: Arc<dyn RelayBufferReservation>,
}

struct Output {
    reply: HomeUdpOutput,
    _charge: Arc<dyn RelayBufferReservation>,
}

pub(super) struct HomeUdpWork {
    path: Option<Arc<dyn HomeDnsPath>>,
    capture: RelayCapture,
    buffers: Arc<dyn RelayBufferAllocator>,
    replies: Arc<dyn RelayBufferAllocator>,
    pending: LinkedList<Pending>,
    output: LinkedList<Output>,
    closed: bool,
}

impl HomeUdpWork {
    /// `replies` is the SAME arena used by Local output, not a new root budget.
    /// Inputs must retain their original immutable capture/policy receive scope.
    pub(super) fn new(
        path: Option<Arc<dyn HomeDnsPath>>,
        capture: RelayCapture,
        buffers: Arc<dyn RelayBufferAllocator>,
        replies: Arc<dyn RelayBufferAllocator>,
    ) -> Self {
        Self {
            path,
            capture,
            buffers,
            replies,
            pending: LinkedList::new(),
            output: LinkedList::new(),
            closed: false,
        }
    }

    /// Admission never polls an exchange. In particular, a silent Home cannot
    /// hold the capture reader or prevent an unrelated query being admitted.
    pub(super) fn submit(
        &mut self,
        query: UdpQuery,
        input: CompletedDatagram,
        timeout: Duration,
        tcp_retry: bool,
        injection_limit: u16,
    ) -> Result<(), IpError> {
        self.revalidate();
        if self.closed || !self.capture.current() {
            return Err(IpError::Stale);
        }
        // A mismatched decoded request must not even authorize upstream I/O.
        query.check_input(&input)?;
        let path = self.path.clone();
        let buffers = self.buffers.clone();
        let answer = async move {
            query
                .answer(
                    path.as_deref(),
                    timeout,
                    tcp_retry,
                    injection_limit,
                    &*buffers,
                )
                .await
        };
        // Fund the retained future, queue nodes and result metadata before any
        // poll. Input/wire/native output have their own existing reservations.
        let charge = self
            .buffers
            .try_reserve(
                std::mem::size_of_val(&answer)
                    + std::mem::size_of::<Pending>()
                    + std::mem::size_of::<Output>()
                    + 2 * BUFFER_OVERHEAD,
            )
            .map_err(|_| IpError::Full)?;
        self.pending.push_back(Pending {
            input,
            answer: Box::pin(answer),
            result: None,
            charge,
        });
        Ok(())
    }

    pub(super) fn revalidate(&mut self) {
        if self.closed || !self.capture.current() {
            self.pending.clear();
            self.output.clear();
        } else {
            // Per-item nodes release their allocation with their credit, unlike
            // a growable queue retaining peak capacity after jobs are retired.
            for _ in 0..self.pending.len() {
                let work = self.pending.pop_front().expect("owned pending work");
                if work.input.current() {
                    self.pending.push_back(work);
                }
            }
            for _ in 0..self.output.len() {
                let work = self.output.pop_front().expect("owned output work");
                if work.reply.current() {
                    self.output.push_back(work);
                }
            }
        }
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.revalidate();
        let mut ready = false;
        for work in &mut self.pending {
            if work.result.is_none()
                && let Poll::Ready(result) = work.answer.as_mut().poll(cx)
            {
                work.result = Some(result);
            }
            ready |= work.result.is_some();
        }
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Cancellation safe: even a failed completion stays owned until process.
    /// Output alone does not wake this future; select sink writability separately.
    pub(super) async fn wait(&mut self) {
        std::future::poll_fn(|cx| self.poll_ready(cx)).await;
    }

    pub(super) fn process(&mut self, receiver: &mut PacketReceiver) {
        self.revalidate();
        for _ in 0..self.pending.len() {
            let mut work = self.pending.pop_front().expect("owned pending work");
            match work.result.take() {
                None => self.pending.push_back(work),
                Some(Ok(reply)) => {
                    if let Ok(reply) = reply.into_output(
                        receiver,
                        work.input,
                        &*self.replies,
                        self.capture.clone(),
                    ) {
                        self.output.push_back(Output {
                            reply,
                            _charge: work.charge,
                        });
                    }
                }
                Some(Err(_)) => {}
            }
        }
        self.revalidate();
    }

    pub(super) fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    /// At most one synchronous packet write. A successful fragment rotates its
    /// job behind siblings; WouldBlock retains the same job/cursor and authority.
    pub(super) fn write_output(
        &mut self,
        sink: &RelaySink,
        write: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        self.revalidate();
        let Some(mut work) = self.output.pop_front() else {
            return Ok(false);
        };
        let result = work.reply.write_output(sink, write);
        if work.reply.has_output() {
            if matches!(result, Ok(true)) {
                self.output.push_back(work);
            } else {
                self.output.push_front(work);
            }
        }
        self.revalidate();
        result
    }

    /// Clear exchange futures first, then join path-owned preparations. Repeating
    /// after cancellation resumes the SAME path close, never loses the owner.
    pub(super) async fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        self.revalidate();
        if let Some(path) = &self.path {
            path.close().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "udp_work_tests.rs"]
mod tests;
