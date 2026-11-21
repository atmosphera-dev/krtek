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
};

use hickory_proto::{
    op::{DnsResponse, Message, MessageType, Metadata, ResponseCode},
    serialize::binary::{BinEncodable, BinEncoder},
};
use mullvad_types::settings::local_network_access::split_dns::{DnsLane, SuffixMatcher};

use super::transport::{ExchangeError, Protocol, decode_message};

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

impl UdpQuery {
    /// `home` is scoped to one Home resolver/policy. Each protocol invocation
    /// needs its own matching Home grant. It must cancel on revocation; it must
    /// never protect/bind a different resolver as a recovery action.
    ///
    /// `tcp_retry` means the current capture can handle this client's Home TCP
    /// retry, not merely that Home accepts TCP. Until that frontend exists it is
    /// false, and an oversized answer becomes SERVFAIL rather than a leaked retry.
    /// `injection_limit` is the actual complete-datagram output capability, not MTU.
    pub(super) async fn answer<F, Fut>(
        self,
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
