//! Shared normalization vectors also consumed by the Android editor tests.

use super::{DnsLane, DomainSuffix, SuffixMatcher};
use hickory_proto::rr::Name;
use serde::Deserialize;

#[derive(Deserialize)]
struct Acceptance {
    accepted: Vec<Accepted>,
    rejected: Vec<String>,
    matching: Vec<Matching>,
}

#[derive(Deserialize)]
struct Accepted {
    input: String,
    canonical: String,
}

#[derive(Deserialize)]
struct Matching {
    entries: Vec<String>,
    canonical: Vec<String>,
    home: Vec<String>,
    ordinary: Vec<String>,
}

fn vectors() -> Acceptance {
    serde_json::from_str(include_str!(
        "../../../../test/fixtures/split_dns_names.json"
    ))
    .expect("shared split DNS acceptance fixture")
}

#[test]
fn split_dns_shared_normalization_acceptance_is_authoritative() {
    let vectors = vectors();
    assert!(!vectors.accepted.is_empty() && !vectors.rejected.is_empty());
    for case in vectors.accepted {
        assert_eq!(
            DomainSuffix::parse(&case.input).unwrap().canonical(),
            case.canonical
        );
    }
    for input in vectors.rejected {
        assert!(DomainSuffix::parse(&input).is_err(), "{input}");
    }
}

#[test]
fn split_dns_shared_match_vectors_preserve_labels_and_canonical_identity() {
    let vectors = vectors();
    assert!(!vectors.matching.is_empty());
    for case in vectors.matching {
        let matcher = SuffixMatcher::compile(case.entries.iter().map(String::as_str)).unwrap();
        assert_eq!(matcher.canonical_entries(), case.canonical);
        assert!(!case.home.is_empty() && !case.ordinary.is_empty());
        for question in case.home {
            assert_eq!(
                matcher.lane_for_name(&Name::from_ascii(&question).unwrap()),
                DnsLane::Home,
                "{question}"
            );
        }
        for question in case.ordinary {
            assert_eq!(
                matcher.lane_for_name(&Name::from_ascii(&question).unwrap()),
                DnsLane::Ordinary,
                "{question}"
            );
        }
    }
}
