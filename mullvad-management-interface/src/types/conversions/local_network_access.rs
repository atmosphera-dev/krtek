use crate::types::{FromProtobufTypeError, proto};
use mullvad_types::settings::local_network_access::{
    LocalBypassRule, LocalNetworkAccess, MAX_CIDRS_PER_RULE, MAX_RULE_NAME_CHARS, MAX_RULES,
    MAX_SSIDS_PER_RULE, SsidIdentity,
};

impl From<&LocalNetworkAccess> for proto::LocalNetworkAccess {
    fn from(policy: &LocalNetworkAccess) -> Self {
        Self {
            enabled: policy.enabled,
            skip_local_rules_for_excluded_apps: Some(policy.skip_local_rules_for_excluded_apps),
            rules: policy
                .rules
                .iter()
                .map(proto::LocalBypassRule::from)
                .collect(),
        }
    }
}

impl From<&LocalBypassRule> for proto::LocalBypassRule {
    fn from(rule: &LocalBypassRule) -> Self {
        Self {
            id: rule.id.to_string(),
            name: rule.name.clone(),
            enabled: rule.enabled,
            cidrs: rule.cidrs.iter().map(ToString::to_string).collect(),
            ssid_ids: rule
                .ssid_ids
                .iter()
                .map(|ssid| ssid.bytes().to_vec())
                .collect(),
        }
    }
}

impl TryFrom<proto::LocalNetworkAccess> for LocalNetworkAccess {
    type Error = FromProtobufTypeError;

    fn try_from(policy: proto::LocalNetworkAccess) -> Result<Self, Self::Error> {
        let mut policy = local_policy_for_update(policy)?;
        policy.deduplicate();
        Ok(policy)
    }
}

/// Expected values are lossless compare tokens, including invalid stored policy.
pub fn local_policy_for_compare_set(
    policy: proto::LocalNetworkAccess,
) -> Result<LocalNetworkAccess, FromProtobufTypeError> {
    read_local_policy(policy)
}

fn local_policy_for_update(
    policy: proto::LocalNetworkAccess,
) -> Result<LocalNetworkAccess, FromProtobufTypeError> {
    // Refuse oversized repeated fields before allocating a second policy.
    if policy.rules.len() > MAX_RULES {
        return Err(FromProtobufTypeError::invalid_argument(
            "too many local rules",
        ));
    }
    let policy = LocalNetworkAccess {
        enabled: policy.enabled,
        skip_local_rules_for_excluded_apps: policy
            .skip_local_rules_for_excluded_apps
            .unwrap_or(true),
        rules: policy
            .rules
            .into_iter()
            .map(LocalBypassRule::try_from)
            .collect::<Result<_, _>>()?,
    };
    policy
        .validate()
        .map_err(|error| FromProtobufTypeError::invalid_argument(error.to_string()))?;
    Ok(policy)
}

pub(super) fn read_local_policy(
    policy: proto::LocalNetworkAccess,
) -> Result<LocalNetworkAccess, FromProtobufTypeError> {
    Ok(LocalNetworkAccess {
        enabled: policy.enabled,
        skip_local_rules_for_excluded_apps: policy
            .skip_local_rules_for_excluded_apps
            .unwrap_or(true),
        rules: policy
            .rules
            .into_iter()
            .map(read_local_rule)
            .collect::<Result<_, _>>()?,
    })
}

impl TryFrom<proto::LocalBypassRule> for LocalBypassRule {
    type Error = FromProtobufTypeError;

    fn try_from(rule: proto::LocalBypassRule) -> Result<Self, Self::Error> {
        if rule.cidrs.len() > MAX_CIDRS_PER_RULE
            || rule.ssid_ids.len() > MAX_SSIDS_PER_RULE
            || rule.name.chars().count() > MAX_RULE_NAME_CHARS
        {
            return Err(FromProtobufTypeError::invalid_argument(
                "local rule exceeds input limits",
            ));
        }
        read_local_rule(rule)
    }
}

fn read_local_rule(rule: proto::LocalBypassRule) -> Result<LocalBypassRule, FromProtobufTypeError> {
    Ok(LocalBypassRule {
        id: super::arg_from_str(&rule.id, "invalid local rule identifier")?,
        name: rule.name,
        enabled: rule.enabled,
        // Parsing errors can contain suggested addresses. Never put their
        // payload into the RPC status or its diagnostic representation.
        cidrs: rule
            .cidrs
            .into_iter()
            .map(|text| super::arg_from_str(&text, "invalid local prefix"))
            .collect::<Result<_, _>>()?,
        ssid_ids: rule
            .ssid_ids
            .into_iter()
            .map(|bytes| {
                SsidIdentity::from_bytes(bytes).ok_or_else(|| {
                    FromProtobufTypeError::invalid_argument("invalid SSID byte identity")
                })
            })
            .collect::<Result<_, _>>()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn policy() -> LocalNetworkAccess {
        LocalNetworkAccess {
            enabled: true,
            skip_local_rules_for_excluded_apps: false,
            rules: vec![LocalBypassRule {
                id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
                name: "test rule".into(),
                enabled: true,
                cidrs: vec![
                    "192.168.240.0/28".parse().unwrap(),
                    "fe80::10/128".parse().unwrap(),
                ],
                ssid_ids: vec![SsidIdentity::from_bytes(vec![0, 255, 65, 32]).unwrap()],
            }],
        }
    }

    #[test]
    fn local_read_conversion_isolated_from_unrelated_settings() {
        let base = mullvad_types::settings::Settings::default();
        // Compare with the original settings read projection. Its existing
        // allowed-IP normalization is not a Local-policy behavior change.
        let base =
            mullvad_types::settings::Settings::try_from(proto::Settings::from(&base)).unwrap();
        let mut semantic = policy();
        semantic.enabled = false;
        semantic.rules[0].cidrs.clear();
        for invalid in [
            semantic.clone(),
            {
                let mut duplicate = policy();
                duplicate.rules.push(duplicate.rules[0].clone());
                duplicate
            },
            {
                let mut long = policy();
                long.rules[0].name = "x".repeat(65);
                long
            },
        ] {
            assert!(invalid.validate().is_err());
            let mut wire = proto::Settings::from(&base);
            wire.local_network_access = Some((&invalid).into());
            let read = crate::types::SettingsRead::try_from(wire).unwrap();
            assert_eq!(read.relay_settings, base.relay_settings);
            assert_eq!(read.tunnel_options, base.tunnel_options);
            assert_eq!(read.api_access_methods, base.api_access_methods);
            assert_eq!(read.local_network_access.policy.as_ref(), Some(&invalid));
            assert!(read.local_network_access.raw().is_none());
            assert_eq!(
                read.into_representable_settings()
                    .unwrap()
                    .local_network_access,
                invalid
            );
        }
        let mut wire = proto::Settings::from(&base);
        wire.local_network_access = None;
        let absent = crate::types::SettingsRead::try_from(wire.clone()).unwrap();
        assert_eq!(
            absent.local_network_access.policy,
            Some(LocalNetworkAccess::default())
        );
        let mut raw = proto::LocalNetworkAccess::from(&policy());
        raw.rules[0].id = "secret-invalid-id".into();
        wire.local_network_access = Some(raw.clone());
        let read = crate::types::SettingsRead::try_from(wire).unwrap();
        assert!(read.local_network_access.policy.is_none());
        assert_eq!(read.local_network_access.raw(), Some(&raw));
        assert_eq!(read.tunnel_options, base.tunnel_options);
        assert!(!format!("{read:?}").contains("secret-invalid-id"));
        assert!(read.into_representable_settings().is_err());
        let malformed_event = crate::client::DaemonEvent::try_from(
            proto::daemon_event::Event::LocalNetworkStatus(proto::LocalNetworkStatus::default()),
        )
        .unwrap();
        assert!(matches!(
            malformed_event,
            crate::client::DaemonEvent::LocalNetworkStatusUnavailable
        ));
    }

    #[test]
    fn local_mutation_validation_and_compare_set_remain_strict() {
        let original = policy();
        let mut invalid = proto::LocalNetworkAccess::from(&original);
        invalid.enabled = false;
        invalid.rules[0].cidrs.clear();
        for (new, expected) in [
            (invalid.clone(), Some((&original).into())),
            ((&original).into(), Some(invalid)),
        ] {
            let update = proto::LocalNetworkPolicyUpdate {
                policy: Some(new),
                expected,
            };
            let new = LocalNetworkAccess::try_from(update.policy.unwrap());
            let expected = update
                .expected
                .map(local_policy_for_compare_set)
                .transpose();
            if new.is_err() {
                assert!(expected.is_ok());
            } else {
                assert_eq!(expected.unwrap().unwrap().rules[0].cidrs, vec![]);
            }
        }
        let mut repeated = original.clone();
        let prefix = repeated.rules[0].cidrs[0];
        let ssid = repeated.rules[0].ssid_ids[0].clone();
        repeated.rules[0].cidrs.push(prefix);
        repeated.rules[0].ssid_ids.push(ssid);
        let wire = proto::LocalNetworkAccess::from(&repeated);
        assert_eq!(
            local_policy_for_compare_set(wire.clone()).unwrap(),
            repeated
        );
        assert_eq!(LocalNetworkAccess::try_from(wire).unwrap(), original);
        assert_eq!(
            proto::SettingsKey::from(mullvad_types::settings::SettingsKey::LocalNetworkAccess)
                as i32,
            13
        );
        let encoded = proto::Settings {
            local_network_access: Some(Default::default()),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(encoded, vec![0x7a, 0]); // Settings field 15, length-delimited.
    }

    #[test]
    fn expected_policy_preserves_invalid_read_snapshots_without_normalizing() {
        let mut stored = policy();
        stored.rules[0].name = "x".repeat(65);
        stored.rules[0].cidrs.clear();
        let read = read_local_policy((&stored).into()).unwrap();
        assert_eq!(read, stored);
        assert_eq!(
            local_policy_for_compare_set((&read).into()).unwrap(),
            stored
        );
        assert!(LocalNetworkAccess::try_from(proto::LocalNetworkAccess::from(&read)).is_err());
    }

    #[test]
    fn wire_round_trip_preserves_policy_and_binary_identities() {
        let original = policy();
        let encoded = proto::LocalNetworkAccess::from(&original).encode_to_vec();
        let decoded = proto::LocalNetworkAccess::decode(encoded.as_slice()).unwrap();
        assert_eq!(LocalNetworkAccess::try_from(decoded).unwrap(), original);
    }

    #[test]
    fn excluded_apps_optional_wire_defaults_and_exact_expected_are_presence_aware() {
        for value in [None, Some(false), Some(true)] {
            let mut wire = proto::LocalNetworkAccess::from(&policy());
            wire.skip_local_rules_for_excluded_apps = value;
            let decoded =
                proto::LocalNetworkAccess::decode(wire.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded.skip_local_rules_for_excluded_apps, value);
            let mut expected = policy();
            expected.skip_local_rules_for_excluded_apps = value.unwrap_or(true);
            assert_eq!(read_local_policy(decoded.clone()).unwrap(), expected);
            assert_eq!(
                LocalNetworkAccess::try_from(decoded.clone()).unwrap(),
                expected
            );
            assert_eq!(local_policy_for_compare_set(decoded).unwrap(), expected);
            assert_eq!(
                proto::LocalNetworkAccess::from(&expected).skip_local_rules_for_excluded_apps,
                Some(value.unwrap_or(true))
            );
        }
        let mut legacy = proto::LocalNetworkAccess::from(&policy());
        legacy.skip_local_rules_for_excluded_apps = None;
        assert_ne!(local_policy_for_compare_set(legacy).unwrap(), policy());
        let legacy_empty = read_local_policy(proto::LocalNetworkAccess::default()).unwrap();
        assert_eq!(legacy_empty, LocalNetworkAccess::default());
        assert!(legacy_empty.skip_local_rules_for_excluded_apps);
    }

    #[test]
    fn policy_update_preserves_absent_and_explicit_empty_expected_values() {
        for expected in [
            None,
            Some(proto::LocalNetworkAccess::default()),
            Some((&policy()).into()),
        ] {
            let update = proto::LocalNetworkPolicyUpdate {
                policy: Some((&policy()).into()),
                expected,
            };
            let decoded =
                proto::LocalNetworkPolicyUpdate::decode(update.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, update);
            assert_eq!(
                LocalNetworkAccess::try_from(decoded.policy.unwrap()).unwrap(),
                policy()
            );
        }
    }

    #[test]
    fn settings_without_policy_default_and_reset_key_is_additive() {
        let mut settings = mullvad_types::settings::Settings::default();
        let mut wire = proto::Settings::from(&settings);
        wire.local_network_access = None;
        let parsed = mullvad_types::settings::Settings::try_from(wire).unwrap();
        assert_eq!(parsed.local_network_access, LocalNetworkAccess::default());
        settings.local_network_access = policy();
        let parsed =
            mullvad_types::settings::Settings::try_from(proto::Settings::from(&settings)).unwrap();
        assert_eq!(parsed.local_network_access, settings.local_network_access);
        let key = mullvad_types::settings::SettingsKey::LocalNetworkAccess;
        let wire_key = proto::SettingsKey::from(key.clone());
        assert_eq!(wire_key as i32, 13);
        assert_eq!(
            mullvad_types::settings::SettingsKey::try_from(wire_key).unwrap(),
            key
        );
    }

    #[test]
    fn invalid_wire_inputs_never_echo_values_in_status_or_debug() {
        for field in 0..4 {
            let mut wire = proto::LocalNetworkAccess::from(&policy());
            match field {
                0 => wire.rules[0].id = "secret-id".into(),
                1 => wire.rules[0].cidrs = vec!["secret-prefix".into()],
                2 => wire.rules[0].cidrs = vec!["192.168.241.27/24".into()],
                _ => {
                    wire.rules[0].ssid_ids =
                        vec![b"secret-ssid-that-is-over-thirty-two-bytes".to_vec()]
                }
            }
            let error = LocalNetworkAccess::try_from(wire).unwrap_err();
            let diagnostic = format!("{error} {error:?}");
            let status: crate::Status = error.into();
            assert_eq!(status.code(), crate::Code::InvalidArgument);
            for secret in ["secret-id", "secret-prefix", "192.168.241", "secret-ssid"] {
                assert!(!diagnostic.contains(secret));
                assert!(!status.message().contains(secret));
            }
        }
    }

    #[test]
    fn wire_limits_reject_excess_before_deduplication() {
        let original = proto::LocalNetworkAccess::from(&policy());
        for field in 0..4 {
            let mut wire = original.clone();
            let rule = &mut wire.rules[0];
            match field {
                0 => rule.cidrs = vec![rule.cidrs[0].clone(); MAX_CIDRS_PER_RULE + 1],
                1 => rule.ssid_ids = vec![rule.ssid_ids[0].clone(); MAX_SSIDS_PER_RULE + 1],
                2 => rule.name = "x".repeat(MAX_RULE_NAME_CHARS + 1),
                _ => wire.rules = vec![rule.clone(); MAX_RULES + 1],
            }
            assert!(LocalNetworkAccess::try_from(wire).is_err());
        }
    }

    #[test]
    fn wire_rejects_duplicate_ids_and_empty_enabled_rules_and_deduplicates_entries() {
        let mut wire = proto::LocalNetworkAccess::from(&policy());
        wire.rules.push(wire.rules[0].clone());
        assert!(LocalNetworkAccess::try_from(wire).is_err());
        let mut wire = proto::LocalNetworkAccess::from(&policy());
        wire.rules[0].cidrs.clear();
        assert!(LocalNetworkAccess::try_from(wire.clone()).is_err());
        wire.rules[0].enabled = false;
        assert_eq!(
            LocalNetworkAccess::try_from(wire).unwrap().rules[0]
                .ssid_ids
                .len(),
            1
        );
        let mut wire = proto::LocalNetworkAccess::from(&policy());
        let rule = &mut wire.rules[0];
        rule.cidrs.push(rule.cidrs[0].clone());
        rule.ssid_ids.push(rule.ssid_ids[0].clone());
        assert_eq!(LocalNetworkAccess::try_from(wire).unwrap(), policy());
    }
}
