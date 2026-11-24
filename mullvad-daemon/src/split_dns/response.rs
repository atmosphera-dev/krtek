//! Local DNS error responses, never applied to upstream reply bytes.
use super::transport::ExchangeError;
use hickory_proto::op::{Edns, Message, Metadata, OpCode, ResponseCode};

// Advertise a local receive size that fits the IPv6 minimum MTU without
// fragmentation. This is not a limit on forwarded queries or replies.
const EDNS_UDP_PAYLOAD: u16 = 1280 - 40 - 8;

pub(super) fn failure(request: &Message, code: ResponseCode) -> Result<Vec<u8>, ExchangeError> {
    let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
    reply.metadata = Metadata::response_from_request(&request.metadata);
    reply.metadata.response_code = match request.queries.as_slice() {
        [question] => {
            reply.add_query(question.clone());
            code
        }
        // RFC 9619: a standard query with QDCOUNT > 1 gets FORMERR with
        // no questions, regardless of why this path generated an error.
        [_, _, ..] if request.metadata.op_code == OpCode::Query => ResponseCode::FormErr,
        _ => code,
    };
    if let Some(request_edns) = request.edns.as_ref().filter(|edns| edns.version() == 0) {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_UDP_PAYLOAD)
            .set_dnssec_ok(request_edns.flags().dnssec_ok);
        reply.set_edns(edns);
    }
    reply.to_vec().map_err(|_| ExchangeError::Malformed)
}
