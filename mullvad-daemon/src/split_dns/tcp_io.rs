//! Hickory framing over the endpoint's injected, byte-credited stream.
use futures::{
    io::{AsyncRead, AsyncWrite},
    ready,
};
use hickory_net::runtime::{DnsTcpStream, TokioTime};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use talpid_lan_forwarder::tcp_service::TcpChannel;

pub(super) struct CodecIo<C>(pub C);

impl<C: TcpChannel + Unpin> AsyncRead for CodecIo<C> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            ready!(self.0.poll_read_ready(cx))?;
            match self.0.try_read(bytes) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
}
impl<C: TcpChannel + Unpin> AsyncWrite for CodecIo<C> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            ready!(self.0.poll_write_ready(cx))?;
            match self.0.try_write(bytes) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.0.shutdown())
    }
}
impl<C: TcpChannel + Unpin + Sync + 'static> DnsTcpStream for CodecIo<C> {
    type Time = TokioTime;
}
