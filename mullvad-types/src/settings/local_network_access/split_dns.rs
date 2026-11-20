//! Split-DNS input normalization and label-boundary matching.
//!
//! Persisted drafts remain strings so a representable invalid policy can be
//! inspected and repaired. Only this compiled representation classifies names;
//! wire question labels never pass through hostname/IDNA input normalization.

use std::{collections::HashSet, fmt, net::IpAddr};

use hickory_proto::{
    op::{Message, MessageType, OpCode},
    rr::{Name, RecordType},
};

#[path = "split_dns_policy.rs"]
mod policy;
pub use policy::{SplitDnsPolicy, SplitDnsPolicyError};

#[cfg(test)]
#[path = "split_dns_vectors.rs"]
mod vectors;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid split DNS domain")]
pub struct DomainError;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DomainSuffix(Name);

impl DomainSuffix {
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        let text = input.trim();
        let text = text.strip_prefix('.').unwrap_or(text);
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty()
            || text.parse::<IpAddr>().is_ok()
            || text
                .chars()
                .any(|c| matches!(c, '*' | '/' | '\\' | ':' | '@' | '[' | ']'))
        {
            return Err(DomainError);
        }
        // No Hickory relaxed fallback. STD3, non-transitional IDNA, hyphen and
        // DNS-length checks reject malformed A-labels instead of treating them
        // as arbitrary ASCII labels. Validate the Unicode/A-label round trip.
        let ascii = idna::domain_to_ascii_strict(text).map_err(|_| DomainError)?;
        let (unicode, result) = idna::domain_to_unicode(&ascii);
        result.map_err(|_| DomainError)?;
        if idna::domain_to_ascii_strict(&unicode).map_err(|_| DomainError)? != ascii
            || ascii.is_empty()
            || ascii.ends_with('.')
            || ascii.parse::<IpAddr>().is_ok()
        {
            return Err(DomainError);
        }
        let mut name = Name::from_ascii(&ascii)
            .map_err(|_| DomainError)?
            .to_lowercase();
        if name.is_root() {
            return Err(DomainError);
        }
        name.set_fqdn(true);
        Ok(Self(name))
    }

    pub fn canonical(&self) -> String {
        self.0.to_ascii()
    }

    pub fn matches(&self, question: &Name) -> bool {
        self.0.zone_of(question)
    }
}

impl fmt::Debug for DomainSuffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DomainSuffix(redacted)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsLane {
    Home,
    Ordinary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QuestionError {
    #[error("malformed split DNS question")]
    Malformed,
    #[error("unsupported split DNS operation")]
    Unsupported,
    #[error("questions select different DNS authorities")]
    MixedLanes,
}

/// Immutable once compiled for a policy revision; no answer cache or alias
/// following. Equal normalized entries deduplicate; overlaps preserve intent.
#[derive(Clone, Default)]
pub struct SuffixMatcher(Vec<DomainSuffix>);

impl SuffixMatcher {
    pub fn compile<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, DomainError> {
        let mut seen = HashSet::new();
        let mut suffixes = Vec::new();
        for text in entries {
            let suffix = DomainSuffix::parse(text)?;
            if seen.insert(suffix.clone()) {
                suffixes.push(suffix);
            }
        }
        Ok(Self(suffixes))
    }

    pub fn canonical_entries(&self) -> Vec<String> {
        self.0.iter().map(DomainSuffix::canonical).collect()
    }

    pub fn lane_for_name(&self, question: &Name) -> DnsLane {
        if self.0.iter().any(|suffix| suffix.matches(question)) {
            DnsLane::Home
        } else {
            DnsLane::Ordinary
        }
    }

    pub fn classify(&self, message: &Message) -> Result<DnsLane, QuestionError> {
        if message.metadata.message_type != MessageType::Query || message.queries.is_empty() {
            return Err(QuestionError::Malformed);
        }
        if message.metadata.op_code != OpCode::Query
            || message
                .queries
                .iter()
                .any(|query| matches!(query.query_type(), RecordType::AXFR | RecordType::IXFR))
        {
            return Err(QuestionError::Unsupported);
        }
        let lane = self.lane_for_name(message.queries[0].name());
        if message
            .queries
            .iter()
            .any(|query| self.lane_for_name(query.name()) != lane)
        {
            return Err(QuestionError::MixedLanes);
        }
        Ok(lane)
    }
}

impl fmt::Debug for SuffixMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SuffixMatcher")
            .field("entry_count", &self.0.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    #[test]
    fn split_dns_normalizes_case_dots_and_idna_with_strict_round_trips() {
        for input in ["home", ".home", "HOME.", " .HoMe. "] {
            assert_eq!(DomainSuffix::parse(input).unwrap().canonical(), "home.");
        }
        let unicode = DomainSuffix::parse("B\u{fc}cher.example").unwrap();
        assert_eq!(unicode.canonical(), "xn--bcher-kva.example.");
        assert_eq!(
            unicode,
            DomainSuffix::parse("XN--BCHER-KVA.EXAMPLE.").unwrap()
        );
        let matcher = SuffixMatcher::compile([
            "home",
            ".HOME.",
            "nas.home",
            "b\u{fc}cher.example",
            "xn--bcher-kva.example",
        ])
        .unwrap();
        assert_eq!(
            matcher.canonical_entries(),
            ["home.", "nas.home.", "xn--bcher-kva.example."]
        );
    }

    #[test]
    fn split_dns_rejects_non_domains_and_protocol_length_violations() {
        for input in [
            "",
            ".",
            "..home",
            "home..",
            "a..home",
            "*",
            "*.home",
            "https://home",
            "home/path",
            "home:53",
            "user@home",
            "127.0.0.1",
            "127.0.0.1.",
            "[::1]",
            "::1",
            "a\\046home",
            "bad name.home",
            "-bad.home",
            "bad-.home",
            "xn--.home",
            "xn--a.home",
        ] {
            assert!(DomainSuffix::parse(input).is_err(), "{input}");
        }
        assert!(DomainSuffix::parse(&format!("{}.home", "a".repeat(64))).is_err());
        assert!(DomainSuffix::parse(&vec!["a".repeat(63); 4].join(".")).is_err());
        assert!(
            DomainSuffix::parse(
                &[
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(61)
                ]
                .join(".")
            )
            .is_ok()
        );
    }

    #[test]
    fn split_dns_matches_dns_labels_not_text_or_alias_targets() {
        let matcher =
            SuffixMatcher::compile(["home", "my-matrix-server.com", "b\u{fc}cher.example"])
                .unwrap();
        for name in [
            "home.",
            "NAS.HOME.",
            "deep.nas.home.",
            "my-matrix-server.com.",
            "_matrix-fed._tcp.my-matrix-server.com.",
            "xn--bcher-kva.example.",
        ] {
            assert_eq!(
                matcher.lane_for_name(&Name::from_ascii(name).unwrap()),
                DnsLane::Home,
                "{name}"
            );
        }
        for name in [
            "myhome.",
            "home.example.",
            "notmy-matrix-server.com.",
            "my-matrix-server.com.evil.",
            "nas.",
            "outside.example.",
            "1.0.0.10.in-addr.arpa.",
            ".",
        ] {
            assert_eq!(
                matcher.lane_for_name(&Name::from_ascii(name).unwrap()),
                DnsLane::Ordinary,
                "{name}"
            );
        }
    }

    #[test]
    fn split_dns_classifies_every_message_and_rejects_mixed_questions() {
        let matcher = SuffixMatcher::compile(["home"]).unwrap();
        let mut request = Message::query();
        assert_eq!(matcher.classify(&request), Err(QuestionError::Malformed));
        for kind in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::SRV,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::TXT,
            RecordType::MX,
            RecordType::CNAME,
            RecordType::Unknown(65400),
        ] {
            request.queries = vec![Query::query(Name::from_ascii("nas.home.").unwrap(), kind)];
            assert_eq!(matcher.classify(&request), Ok(DnsLane::Home));
        }
        request.add_query(Query::query(
            Name::from_ascii("unlisted.example.").unwrap(),
            RecordType::A,
        ));
        assert_eq!(matcher.classify(&request), Err(QuestionError::MixedLanes));
        request.queries.remove(0);
        assert_eq!(matcher.classify(&request), Ok(DnsLane::Ordinary));
        request.metadata.op_code = OpCode::Update;
        assert_eq!(matcher.classify(&request), Err(QuestionError::Unsupported));
    }

    #[test]
    fn split_dns_diagnostics_do_not_expose_domains() {
        let matcher = SuffixMatcher::compile(["secret.home"]).unwrap();
        assert_eq!(format!("{matcher:?}"), "SuffixMatcher { entry_count: 1 }");
        assert_eq!(
            format!("{:?}", DomainSuffix::parse("secret.home").unwrap()),
            "DomainSuffix(redacted)"
        );
    }
}
