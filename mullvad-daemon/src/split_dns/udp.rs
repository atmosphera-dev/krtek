//! Selective handling of a complete captured UDP DNS message. Inactive until
//! attached to the capture owner. IP completion, resource admission, capture
//! generation and final sink/grant checks remain that owner's responsibilities.
//!
//! In particular PassThrough borrows the original bytes: the caller releases its
//! original packet(s), not a parsed/reserialized replacement. Home exchange is
//! injected with no Ordinary capability, so failure cannot choose another lane.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use hickory_proto::{
    op::{DnsResponse, Message, MessageType, Metadata, ResponseCode},
    serialize::binary::{BinEncodable, BinEncoder},
};
use mullvad_types::settings::local_network_access::split_dns::{DnsLane, SuffixMatcher};
use talpid_lan_forwarder::packet_receiver::{
    CompletedDatagram, DatagramReply, IpError, PacketReceiver,
};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayBufferAllocator, RelayBufferReservation, RelayCapture, RelaySink,
};

use super::{
    home_path::{HomeDnsPath, HomeDnsQuery},
    transport::{ExchangeError, Protocol, decode_message},
};

pub(super) enum UdpDecision<'a> {
    PassThrough(&'a [u8]),
    Drop,
    Intercept(Box<UdpQuery>),
}

pub(super) struct UdpQuery {
    client: SocketAddr,
    resolver: SocketAddr,
    request: Message,
    error: Option<ResponseCode>,
}

/// Only call with a checksum-validated, complete UDP payload and the resolver
/// list belonging to the same capture generation. No Home eligibility decision
/// occurs here: a listed name stays intercepted even when Home is ineligible.
pub(super) fn inspect<'a>(
    matcher: Option<&SuffixMatcher>,
    advertised: &[IpAddr],
    client: SocketAddr,
    resolver: SocketAddr,
    bytes: &'a [u8],
) -> UdpDecision<'a> {
    let Some(matcher) = matcher else {
        return UdpDecision::PassThrough(bytes);
    };
    if resolver.port() != 53 || !advertised.contains(&resolver.ip()) {
        return UdpDecision::PassThrough(bytes);
    }
    let Ok(request) = decode_message(bytes) else {
        // No partial name or hand-decoded header can authorize forwarding.
        return UdpDecision::Drop;
    };
    if request.metadata.message_type != MessageType::Query {
        return UdpDecision::Drop;
    }
    if !request
        .queries
        .iter()
        .any(|q| matcher.lane_for_name(q.name()) == DnsLane::Home)
    {
        return UdpDecision::PassThrough(bytes);
    }
    let error = if request.queries.len() != 1 {
        Some(ResponseCode::FormErr)
    } else if matcher.classify(&request).is_err() {
        Some(ResponseCode::NotImp)
    } else {
        None
    };
    UdpDecision::Intercept(Box::new(UdpQuery {
        client,
        resolver,
        request,
        error,
    }))
}

/// Message result, not permission to inject. The capture owner must retain and
/// recheck the exact capture generation and Home grant before every final write.
pub(super) struct UdpReply {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub bytes: Vec<u8>,
}

/// Owns Home authority until the last client-facing fragment or retry is gone.
/// No raw reply extraction: a native output job retains this guard and invokes
/// `with_current` for every packet, inside its existing capture/sink check.
/// This guard checks Home lifetime only; it does not grant capture authority.
pub(super) struct HomeUdpReply {
    reply: UdpReply,
    request: Message,
    leases: [Option<Arc<dyn HomeDnsQuery>>; 2],
    _storage: Arc<dyn RelayBufferReservation>,
}

impl HomeUdpReply {
    /// Bind the retained Home result to its exact completed capture tuple before
    /// native generation. The output owns both guards until the final fragment.
    pub(super) fn into_output(
        self,
        receiver: &mut PacketReceiver,
        input: CompletedDatagram,
        replies: &dyn RelayBufferAllocator,
        capture: RelayCapture,
    ) -> Result<HomeUdpOutput, IpError> {
        let output = self
            .with_current(|source, destination, bytes| {
                let packet = input.packet()?;
                let flow = packet.flow;
                if flow.source != destination || flow.destination != source {
                    return Err(IpError::Malformed);
                }
                if decode_message(packet.payload).map_err(|_| IpError::Malformed)? != self.request {
                    return Err(IpError::Malformed);
                }
                receiver.reply(input, bytes, replies)
            })
            .map_err(|_| IpError::Stale)??;
        Ok(HomeUdpOutput {
            output: Some((self, output)),
            capture,
        })
    }

    pub(super) fn with_current<T>(
        &self,
        emit: impl FnOnce(SocketAddr, SocketAddr, &[u8]) -> T,
    ) -> Result<T, ExchangeError> {
        if !self.leases.iter().flatten().all(|lease| lease.current()) {
            return Err(ExchangeError::Closed);
        }
        Ok(emit(
            self.reply.source,
            self.reply.destination,
            &self.reply.bytes,
        ))
    }
}

/// Native output is inaccessible without its original Home reply authority.
/// The frontend still supplies the exact capture/sink-checked synchronous writer.
pub(super) struct HomeUdpOutput {
    output: Option<(HomeUdpReply, DatagramReply)>,
    capture: RelayCapture,
}

impl HomeUdpOutput {
    pub(super) fn current(&self) -> bool {
        self.capture.current()
            && self.output.as_ref().is_some_and(|(authority, output)| {
                authority.with_current(|_, _, _| ()).is_ok() && output.current()
            })
    }

    pub(super) fn has_output(&self) -> bool {
        self.output.is_some()
    }

    pub(super) fn write_output(
        &mut self,
        sink: &RelaySink,
        write: impl FnOnce(&[u8]) -> std::io::Result<usize>,
    ) -> std::io::Result<bool> {
        let Some((authority, output)) = self.output.as_mut() else {
            return Ok(false);
        };
        if !sink
            .identity()
            .sources
            .contains(authority.reply.destination.ip())
        {
            self.output.take();
            return Ok(false);
        }
        let result = authority.with_current(|_, _, _| {
            output.write_output(sink.identity().mtu, |bytes| {
                self.capture
                    .with_sink(sink, || write(bytes))
                    .map_err(|_| std::io::Error::other("DNS capture sink retired"))?
            })
        });
        let drained = !output.has_output();
        match result {
            Err(_) => {
                self.output.take();
                Ok(false)
            }
            Ok(result) => {
                if drained {
                    self.output.take();
                }
                result
            }
        }
    }
}

impl UdpQuery {
    pub(super) fn check_input(&self, input: &CompletedDatagram) -> Result<(), IpError> {
        let packet = input.packet()?;
        if packet.flow.source != self.client
            || packet.flow.destination != self.resolver
            || decode_message(packet.payload).map_err(|_| IpError::Malformed)? != self.request
        {
            return Err(IpError::Malformed);
        }
        Ok(())
    }

    /// Acquire through the selected Home path only. Preserve every acquired
    /// lease, including the UDP lease when Home TC requires a TCP exchange.
    /// Denied/unavailable paths produce SERVFAIL; retirement suppresses the whole
    /// result rather than allowing a successor path to revive this query.
    pub(super) async fn answer(
        self,
        path: Option<&dyn HomeDnsPath>,
        timeout: Duration,
        tcp_retry: bool,
        injection_limit: u16,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<HomeUdpReply, ExchangeError> {
        // Complete wire response plus library-produced truncation may coexist.
        // Keep this wire-storage peak charged before exchange through final use.
        let storage = buffers
            .try_reserve(2 * (usize::from(u16::MAX) + 1) + BUFFER_OVERHEAD)
            .map_err(|_| ExchangeError::Io(std::io::ErrorKind::OutOfMemory.into()))?;
        let client = self.client;
        let mut leases: [Option<Arc<dyn HomeDnsQuery>>; 2] = [None, None];
        let reply = self
            .answer_with(
                |protocol, message| {
                    let previous = leases[0].clone();
                    let query = if leases.iter().flatten().all(|lease| lease.current()) {
                        path.ok_or(ExchangeError::Closed)
                            .and_then(|path| path.authorize(client, protocol))
                            .map(Arc::<dyn HomeDnsQuery>::from)
                    } else {
                        Err(ExchangeError::Closed)
                    };
                    if let Ok(query) = &query {
                        let index = match protocol {
                            Protocol::Udp => 0,
                            Protocol::Tcp => 1,
                        };
                        leases[index] = Some(query.clone());
                    }
                    async move {
                        let query = query?;
                        tokio::select! {
                            biased;
                            _ = async {
                                match previous {
                                    Some(query) => query.retired().await,
                                    None => std::future::pending().await,
                                }
                            } => Err(ExchangeError::Closed),
                            _ = query.retired() => Err(ExchangeError::Closed),
                            result = query.exchange(timeout, message) => result,
                        }
                    }
                },
                tcp_retry,
                injection_limit,
            )
            .await?;
        let reply = HomeUdpReply {
            reply,
            request: self.request,
            leases,
            _storage: storage,
        };
        reply.with_current(|_, _, _| ())?;
        Ok(reply)
    }

    /// `home` is scoped to one Home resolver/policy. Each protocol invocation
    /// needs its own matching Home grant. It must cancel on revocation; it must
    /// never protect/bind a different resolver as a recovery action.
    ///
    /// `tcp_retry` means the current capture can handle this client's Home TCP
    /// retry, not merely that Home accepts TCP. Until that frontend exists it is
    /// false, and an oversized answer becomes SERVFAIL rather than a leaked retry.
    /// `injection_limit` is the actual complete-datagram output capability, not MTU.
    async fn answer_with<F, Fut>(
        &self,
        mut home: F,
        tcp_retry: bool,
        injection_limit: u16,
    ) -> Result<UdpReply, ExchangeError>
    where
        F: FnMut(Protocol, Message) -> Fut,
        Fut: Future<Output = Result<DnsResponse, ExchangeError>>,
    {
        let bytes = if let Some(error) = self.error {
            self.failure(error)?
        } else {
            match self.home_answer(&mut home).await {
                Ok(response) => self.fit(response, tcp_retry, injection_limit)?,
                Err(_) => self.failure(ResponseCode::ServFail)?,
            }
        };
        Ok(UdpReply {
            source: self.resolver,
            destination: self.client,
            bytes,
        })
    }

    async fn home_answer<F, Fut>(&self, home: &mut F) -> Result<DnsResponse, ExchangeError>
    where
        F: FnMut(Protocol, Message) -> Fut,
        Fut: Future<Output = Result<DnsResponse, ExchangeError>>,
    {
        let mut response = home(Protocol::Udp, self.request.clone()).await?;
        self.check(&response)?;
        if response.metadata.truncation {
            response = home(Protocol::Tcp, self.request.clone()).await?;
            self.check(&response)?;
            if response.metadata.truncation {
                return Err(ExchangeError::Malformed);
            }
        }
        Ok(response)
    }

    fn check(&self, response: &DnsResponse) -> Result<(), ExchangeError> {
        if response.metadata.message_type != MessageType::Response
            || response.metadata.id != self.request.metadata.id
            || response.metadata.op_code != self.request.metadata.op_code
            || response.queries != self.request.queries
        {
            return Err(ExchangeError::Identity);
        }
        Ok(())
    }

    fn failure(&self, code: ResponseCode) -> Result<Vec<u8>, ExchangeError> {
        let mut response =
            Message::response(self.request.metadata.id, self.request.metadata.op_code);
        response.metadata = Metadata::response_from_request(&self.request.metadata);
        response.metadata.response_code = code;
        response.queries = self.request.queries.clone();
        response.to_vec().map_err(|_| ExchangeError::Malformed)
    }

    fn fit(
        &self,
        response: DnsResponse,
        tcp_retry: bool,
        injection_limit: u16,
    ) -> Result<Vec<u8>, ExchangeError> {
        let limit = self.request.max_payload().min(injection_limit);
        if response.as_buffer().len() <= usize::from(limit) {
            // Preserve compression, unknown data, TTLs and Home's negative/error
            // responses exactly when the complete wire response fits.
            return Ok(response.as_buffer().to_vec());
        }
        if !tcp_retry {
            return self.failure(ResponseCode::ServFail);
        }
        // Hickory rolls back incomplete records and sets TC in the emitted
        // header. Never slice raw records or clear a received TC bit.
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(limit);
        response
            .into_message()
            .emit(&mut encoder)
            .map_err(|_| ExchangeError::Malformed)?;
        // Record rollback moves the cursor; trim discards the abandoned bytes
        // beyond it, which a strict complete-message decoder must not receive.
        encoder.trim();
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "udp_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "udp_path_tests.rs"]
mod path_tests;
