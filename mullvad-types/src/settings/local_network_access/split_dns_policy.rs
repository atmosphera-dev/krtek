//! Persisted split-DNS draft, distinct from ordinary DNS preferences.

use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::LocalBypassRule;
use super::{DomainError, SuffixMatcher};

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct SplitDnsPolicy {
    pub enabled: bool,
    pub suffixes: Vec<String>,
    pub home_resolver: Option<IpAddr>,
    pub local_rule_id: Option<Uuid>,
}

impl fmt::Debug for SplitDnsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitDnsPolicy")
            .field("enabled", &self.enabled)
            .field("suffix_count", &self.suffixes.len())
            .field("has_resolver", &self.home_resolver.is_some())
            .field("has_association", &self.local_rule_id.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SplitDnsPolicyError {
    #[error("invalid split DNS domain")]
    InvalidDomain,
    #[error("enabled split DNS has no domains")]
    MissingSuffix,
    #[error("enabled split DNS has no Home resolver")]
    MissingResolver,
    #[error("enabled split DNS has no Local rule association")]
    MissingAssociation,
    #[error("split DNS references an absent Local rule")]
    UnknownAssociation,
    #[error("the associated Local rule does not cover the Home resolver")]
    ResolverNotCovered,
}

impl SplitDnsPolicy {
    pub fn validate(&self, rules: &[LocalBypassRule]) -> Result<(), SplitDnsPolicyError> {
        // Disabled drafts may be incomplete. Provided names still use the one
        // strict normalization contract; loading never replaces invalid strings.
        SuffixMatcher::compile(self.suffixes.iter().map(String::as_str))
            .map_err(|_| SplitDnsPolicyError::InvalidDomain)?;
        if !self.enabled {
            return Ok(());
        }
        if self.suffixes.is_empty() {
            return Err(SplitDnsPolicyError::MissingSuffix);
        }
        let resolver = self
            .home_resolver
            .ok_or(SplitDnsPolicyError::MissingResolver)?;
        let id = self
            .local_rule_id
            .ok_or(SplitDnsPolicyError::MissingAssociation)?;
        let rule = rules
            .iter()
            .find(|rule| rule.id == id)
            .ok_or(SplitDnsPolicyError::UnknownAssociation)?;
        if !rule.cidrs.iter().any(|cidr| cidr.contains(resolver)) {
            return Err(SplitDnsPolicyError::ResolverNotCovered);
        }
        // Rule/master enablement, network identity, permissions and current
        // target/interface collisions are availability/authority checks. Saving
        // a policy never switches a Local rule on or broadens its prefixes.
        Ok(())
    }

    /// Called only for an accepted replacement. Expected tokens and stored
    /// invalid reads retain their exact strings, order and incomplete fields.
    pub fn normalize_suffixes(&mut self) -> Result<(), DomainError> {
        self.suffixes =
            SuffixMatcher::compile(self.suffixes.iter().map(String::as_str))?.canonical_entries();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> LocalBypassRule {
        LocalBypassRule {
            id: Uuid::from_u128(11),
            name: "synthetic home".into(),
            enabled: false,
            cidrs: vec!["10.77.10.0/24".parse().unwrap()],
            ssid_ids: vec![],
        }
    }

    fn policy(rule: &LocalBypassRule) -> SplitDnsPolicy {
        SplitDnsPolicy {
            enabled: true,
            suffixes: vec![".HOME.".into()],
            home_resolver: Some("10.77.10.53".parse().unwrap()),
            local_rule_id: Some(rule.id),
        }
    }

    #[test]
    fn split_dns_absence_is_disabled_and_incomplete_disabled_drafts_round_trip() {
        let absent: SplitDnsPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(absent, SplitDnsPolicy::default());
        assert_eq!(absent.validate(&[]), Ok(()));
        let draft = SplitDnsPolicy {
            suffixes: vec!["home".into()],
            local_rule_id: Some(Uuid::from_u128(99)),
            ..SplitDnsPolicy::default()
        };
        assert_eq!(draft.validate(&[]), Ok(()));
        assert_eq!(
            serde_json::from_str::<SplitDnsPolicy>(&serde_json::to_string(&draft).unwrap())
                .unwrap(),
            draft
        );
    }

    #[test]
    fn split_dns_enabling_requires_complete_covered_association_without_enabling_local() {
        let rule = rule();
        let complete = policy(&rule);
        assert_eq!(complete.validate(std::slice::from_ref(&rule)), Ok(()));
        assert!(!rule.enabled);
        let mut missing = complete.clone();
        missing.suffixes.clear();
        assert_eq!(
            missing.validate(std::slice::from_ref(&rule)),
            Err(SplitDnsPolicyError::MissingSuffix)
        );
        missing = complete.clone();
        missing.home_resolver = None;
        assert_eq!(
            missing.validate(std::slice::from_ref(&rule)),
            Err(SplitDnsPolicyError::MissingResolver)
        );
        missing = complete.clone();
        missing.local_rule_id = None;
        assert_eq!(
            missing.validate(std::slice::from_ref(&rule)),
            Err(SplitDnsPolicyError::MissingAssociation)
        );
        assert_eq!(
            complete.validate(&[]),
            Err(SplitDnsPolicyError::UnknownAssociation)
        );
        missing = complete;
        missing.home_resolver = Some("1.1.1.1".parse().unwrap());
        assert_eq!(
            missing.validate(std::slice::from_ref(&rule)),
            Err(SplitDnsPolicyError::ResolverNotCovered)
        );
    }

    #[test]
    fn split_dns_invalid_representable_read_retains_exact_fields_for_repair() {
        let rule = rule();
        let mut invalid = policy(&rule);
        invalid.suffixes = vec!["*.home".into(), "*.home".into()];
        let bytes = serde_json::to_string(&invalid).unwrap();
        let mut read: SplitDnsPolicy = serde_json::from_str(&bytes).unwrap();
        assert_eq!(read, invalid);
        assert_eq!(
            read.validate(std::slice::from_ref(&rule)),
            Err(SplitDnsPolicyError::InvalidDomain)
        );
        assert!(read.normalize_suffixes().is_err());
        assert_eq!(read, invalid);
        assert_eq!(serde_json::to_string(&read).unwrap(), bytes);
    }

    #[test]
    fn split_dns_replacement_normalization_deduplicates_without_losing_resolver_or_association() {
        let rule = rule();
        let mut configured = policy(&rule);
        configured.suffixes.extend([
            "home".into(),
            "nas.home".into(),
            "b\u{fc}cher.example".into(),
            "XN--BCHER-KVA.EXAMPLE.".into(),
        ]);
        configured.normalize_suffixes().unwrap();
        assert_eq!(
            configured.suffixes,
            ["home.", "nas.home.", "xn--bcher-kva.example."]
        );
        assert_eq!(configured.home_resolver, policy(&rule).home_resolver);
        assert_eq!(configured.local_rule_id, Some(rule.id));
        let diagnostic = format!("{configured:?}");
        assert!(
            !diagnostic.contains("10.77")
                && !diagnostic.contains("home.")
                && !diagnostic.contains("bcher")
                && !diagnostic.contains(&rule.id.to_string())
        );
    }
}
