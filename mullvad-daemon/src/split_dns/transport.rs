//! Complete-message DNS exchange over an injected, already authorized I/O runtime.
//!
//! This module never chooses a resolver or obtains physical socket authority. A
//! runtime belongs to exactly one admitted Home grant or Ordinary carrier. The
//! caller retains that authority through final emission; transport completion is
//! not permission to write a reply into a successor capture.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use futures::StreamExt;
use hickory_net::{
    runtime::{DnsUdpSocket, RuntimeProvider, Time},
    tcp::TcpStream,
    xfer::DnsStreamHandle,
};
use hickory_proto::{
    op::{DnsResponse, Message, MessageType, OpCode, SerialMessage},
    rr::RecordType,
    serialize::binary::{BinDecodable, BinDecoder, BinEncoder},
};

/// DNS-over-TCP's two-byte frame length is the largest complete DNS message.
/// A full UDP datagram fits too, independently of EDNS and capture MTU.
pub(super) const MAX_MESSAGE_BYTES: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Protocol {
    Udp,
    Tcp,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExchangeError {
    #[error("DNS transport failed")]
    Transport(#[from] hickory_net::NetError),
    #[error("DNS I/O failed")]
    Io(#[from] io::Error),
    #[error("malformed DNS message")]
    Malformed,
    #[error("unsupported DNS operation")]
    Unsupported,
    #[error("DNS transport closed without a response")]
    Closed,
    #[error("DNS response identity does not match the request")]
    Identity,
}

/// One exchange, with no answer cache, alias chasing or alternate resolver.
///
/// All message sections and request options pass through Hickory's message
/// transport, not its high-level resolver. TCP framing is owned by Hickory.
pub(super) async fn exchange<P: RuntimeProvider>(
    provider: P,
    resolver: SocketAddr,
    protocol: Protocol,
    timeout: Duration,
    message: Message,
) -> Result<DnsResponse, ExchangeError> {
    if message.metadata.message_type != MessageType::Query || message.queries.is_empty() {
        return Err(ExchangeError::Malformed);
    }
    if message.metadata.op_code != OpCode::Query
        || message
            .queries
            .iter()
            .any(|q| matches!(q.query_type(), RecordType::AXFR | RecordType::IXFR))
    {
        return Err(ExchangeError::Unsupported);
    }

    // Never reuse the application's transaction ID as upstream entropy. Each
    // socket and stream is scoped to this exchange and exactly one injected
    // runtime authority. The reply restores only the client ID, byte-for-byte
    // preserving compression, unknown records, signatures and all TTLs.
    let client_id = message.metadata.id;
    let mut request = message;
    request.metadata.id = Message::query().metadata.id;
    let bytes = request.to_vec().map_err(|_| ExchangeError::Malformed)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ExchangeError::Malformed);
    }

    let reply = P::Timer::timeout(timeout, async move {
        match protocol {
            Protocol::Udp => {
                let ip = if resolver.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                };
                // The injected binding performs Home protect/bind or exact
                // carrier preparation. The production adapter must not replace
                // it with an unscoped Tokio/OS socket.
                let socket = provider.bind_udp(SocketAddr::new(ip, 0), resolver).await?;
                if socket.send_to(&bytes, resolver).await? != bytes.len() {
                    return Err(ExchangeError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "incomplete DNS datagram send",
                    )));
                }
                let mut buffer = vec![0; MAX_MESSAGE_BYTES];
                let (len, peer) = socket.recv_from(&mut buffer).await?;
                if peer.ip().to_canonical() != resolver.ip().to_canonical()
                    || peer.port() != resolver.port()
                {
                    return Err(ExchangeError::Identity);
                }
                buffer.truncate(len);
                validate_reply(buffer, &request)
            }
            Protocol::Tcp => {
                let socket = provider.connect_tcp(resolver, None, Some(timeout)).await?;
                let (mut stream, mut sender) = TcpStream::from_stream(socket, resolver);
                sender.send(SerialMessage::new(bytes, resolver))?;
                let reply = stream.next().await.ok_or(ExchangeError::Closed)??;
                validate_reply(reply.into_parts().0, &request)
            }
        }
    })
    .await??;

    restore_client_id(reply, client_id)
}

/// Decode exactly one complete library message; Hickory's convenience
/// `Message::from_vec` permits trailing bytes and is insufficient here.
pub(super) fn decode_message(bytes: &[u8]) -> Result<Message, ExchangeError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ExchangeError::Malformed);
    }
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder).map_err(|_| ExchangeError::Malformed)?;
    if !decoder.is_empty() {
        return Err(ExchangeError::Malformed);
    }
    Ok(message)
}

fn validate_reply(bytes: Vec<u8>, request: &Message) -> Result<DnsResponse, ExchangeError> {
    let response = decode_message(&bytes)?;
    if response.metadata.message_type != MessageType::Response
        || response.metadata.id != request.metadata.id
        || response.metadata.op_code != request.metadata.op_code
        || response.queries != request.queries
    {
        return Err(ExchangeError::Identity);
    }
    DnsResponse::from_buffer(bytes).map_err(|_| ExchangeError::Malformed)
}

fn restore_client_id(response: DnsResponse, id: u16) -> Result<DnsResponse, ExchangeError> {
    let mut buffer = Vec::with_capacity(response.as_buffer().len());
    BinEncoder::new(&mut buffer)
        .emit_u16(id)
        .map_err(|_| ExchangeError::Malformed)?;
    // The codec wrote the header's first field. The rest of the validated
    // original response is opaque and must not be reconstructed or shortened.
    buffer.extend_from_slice(&response.as_buffer()[buffer.len()..]);
    DnsResponse::from_buffer(buffer).map_err(|_| ExchangeError::Malformed)
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
