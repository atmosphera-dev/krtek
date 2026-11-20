use super::*;
use mullvad_types::settings::local_network_access::{
    LocalBypassRule, LocalNetworkAccess, SsidIdentity, split_dns::SplitDnsPolicy,
};

fn policy() -> LocalNetworkAccess {
    LocalNetworkAccess {
        enabled: true,
        skip_local_rules_for_excluded_apps: false,
        split_dns: Default::default(),
        rules: vec![LocalBypassRule {
            id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
            name: "private-rule-marker".into(),
            enabled: true,
            cidrs: vec!["192.168.240.0/28".parse().unwrap()],
            ssid_ids: vec![SsidIdentity::from_bytes(b"private-wifi-marker".to_vec()).unwrap()],
        }],
    }
}

fn persister(path: PathBuf) -> SettingsPersister {
    SettingsPersister {
        path,
        settings: Settings {
            allow_lan: true,
            local_network_access: policy(),
            ..Settings::default()
        },
        on_change_listeners: vec![],
    }
}

#[test]
fn archive_format_settings_keep_unrelated_values_and_exact_conditions() {
    let bytes = br#"{
        "settings_version": 18,
        "allow_lan": true,
        "show_beta_releases": true,
        "local_network_access": {
            "enabled": true,
            "rules": [{
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "archive sample",
                "enabled": true,
                "cidrs": ["192.168.240.0/28"],
                "ssid_ids": ["00ff4120"]
            }]
        }
    }"#;
    let settings = SettingsPersister::load_from_bytes(bytes).unwrap();
    assert!(settings.allow_lan && settings.show_beta_releases);
    assert!(settings.local_network_access.enabled);
    assert!(
        settings
            .local_network_access
            .skip_local_rules_for_excluded_apps
    );
    assert_eq!(
        settings.local_network_access.rules[0].ssid_ids[0].bytes(),
        &[0, 255, 65, 32]
    );
    assert_eq!(
        SettingsPersister::load_from_bytes(&serde_json::to_vec(&settings).unwrap()).unwrap(),
        settings
    );
    let old = SettingsPersister::load_from_bytes(br#"{"allow_lan":true}"#).unwrap();
    assert!(old.allow_lan);
    assert_eq!(old.local_network_access, LocalNetworkAccess::default());
    assert!(old.local_network_access.skip_local_rules_for_excluded_apps);
}

#[tokio::test]
async fn reset_preserves_policy_only_when_its_key_is_requested() {
    // Upstream reset skips its disk save under cfg(test); this checks the key
    // contract, not disk persistence of reset.
    let mut settings = persister(PathBuf::new());
    settings
        .reset(SettingsKeyList {
            keys: vec![SettingsKey::LocalNetworkAccess],
        })
        .await
        .unwrap();
    assert_eq!(settings.local_network_access, policy());
    assert!(!settings.allow_lan);
    settings.reset(SettingsKeyList::default()).await.unwrap();
    assert_eq!(settings.local_network_access, LocalNetworkAccess::default());
}

#[test]
fn settings_diagnostics_contain_counts_without_rule_contents() {
    let settings = persister(PathBuf::new());
    let diagnostic = format!("{} {:?}", settings.summary(), settings.to_settings());
    assert!(diagnostic.contains("local rules: 1"));
    for secret in [
        "private-rule-marker",
        "private-wifi-marker",
        "707269766174652d776966692d6d61726b6572",
        "192.168.240",
    ] {
        assert!(!diagnostic.contains(secret));
    }
}

fn dns_policy() -> LocalNetworkAccess {
    let mut policy = policy();
    policy.split_dns = SplitDnsPolicy {
        enabled: true,
        suffixes: vec![".HOME.".into(), "home".into(), "nas.home".into()],
        home_resolver: Some("192.168.240.10".parse().unwrap()),
        local_rule_id: Some(policy.rules[0].id),
    };
    policy
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("krtek-policy-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn settings(&self) -> SettingsPersister {
        let mut settings = persister(self.0.join(SETTINGS_FILE));
        settings.settings.local_network_access = LocalNetworkAccess::default();
        settings
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn committed_policy_is_read_back_before_notification_and_noop_is_silent() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    let count = Arc::new(AtomicUsize::new(0));
    let observer = count.clone();
    let path = settings.path.clone();
    settings.register_change_listener(move |updated| {
        let on_disk = SettingsPersister::load_from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk, *updated);
        assert_eq!(on_disk.local_network_access, policy());
        observer.fetch_add(1, Ordering::SeqCst);
    });
    assert!(
        settings
            .set_local_network_access(policy(), None)
            .await
            .unwrap()
    );
    let loaded = SettingsPersister::load_from_file(&settings.path)
        .await
        .unwrap();
    assert_eq!(loaded.local_network_access, policy());
    assert!(loaded.allow_lan);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        !settings
            .set_local_network_access(policy(), Some(policy()))
            .await
            .unwrap()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_policy_and_failed_write_preserve_memory_disk_and_notifications() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    settings
        .set_local_network_access(policy(), None)
        .await
        .unwrap();
    let path = settings.path.clone();
    let original = settings.to_settings();
    let bytes = std::fs::read(&path).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observer = count.clone();
    settings.register_change_listener(move |_| {
        observer.fetch_add(1, Ordering::SeqCst);
    });
    let mut invalid = policy();
    invalid.rules[0].cidrs.clear();
    let error = settings
        .set_local_network_access(invalid, None)
        .await
        .unwrap_err();
    let status: mullvad_management_interface::Status = error.into();
    assert_eq!(
        status.code(),
        mullvad_management_interface::Code::InvalidArgument
    );
    assert_eq!(settings.to_settings(), original);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let forbidden = scratch.0.join("existing-directory");
    std::fs::create_dir(&forbidden).unwrap();
    settings.path = forbidden.clone();
    let mut toggled = policy();
    toggled.skip_local_rules_for_excluded_apps = true;
    let error = settings
        .set_local_network_access(toggled, None)
        .await
        .unwrap_err();
    let status: mullvad_management_interface::Status = error.into();
    assert_eq!(
        status.code(),
        mullvad_management_interface::Code::FailedPrecondition
    );
    assert_eq!(settings.to_settings(), original);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(forbidden.is_dir());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stale_expected_cannot_overwrite_concurrent_policy_but_current_expected_can() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    let stale = settings.local_network_access.clone();
    settings
        .set_local_network_access(policy(), None)
        .await
        .unwrap();
    let original = settings.to_settings();
    let bytes = std::fs::read(&settings.path).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observer = count.clone();
    settings.register_change_listener(move |_| {
        observer.fetch_add(1, Ordering::SeqCst);
    });
    let error = settings
        .set_local_network_access(LocalNetworkAccess::default(), Some(stale))
        .await
        .unwrap_err();
    let status: mullvad_management_interface::Status = error.into();
    assert_eq!(status.code(), mullvad_management_interface::Code::Aborted);
    assert_eq!(settings.to_settings(), original);
    assert_eq!(std::fs::read(&settings.path).unwrap(), bytes);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    settings
        .set_local_network_access(LocalNetworkAccess::default(), Some(policy()))
        .await
        .unwrap();
    assert_eq!(
        SettingsPersister::load_from_file(&settings.path)
            .await
            .unwrap()
            .local_network_access,
        LocalNetworkAccess::default()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn excluded_apps_toggle_and_rule_edits_share_one_exact_disk_compare_token() {
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    settings
        .set_local_network_access(policy(), None)
        .await
        .unwrap();
    let off = settings.local_network_access.clone();
    let mut on = off.clone();
    on.skip_local_rules_for_excluded_apps = true;
    let mut edited = off.clone();
    edited.rules[0].name = "edited-rule".into();
    settings
        .set_local_network_access(on.clone(), Some(off.clone()))
        .await
        .unwrap();
    assert!(
        settings
            .set_local_network_access(edited.clone(), Some(off.clone()))
            .await
            .is_err()
    );
    assert_eq!(
        SettingsPersister::load_from_file(&settings.path)
            .await
            .unwrap()
            .local_network_access,
        on
    );
    settings
        .set_local_network_access(edited.clone(), Some(on.clone()))
        .await
        .unwrap();
    assert!(
        settings
            .set_local_network_access(on, Some(off))
            .await
            .is_err()
    );
    assert_eq!(
        SettingsPersister::load_from_file(&settings.path)
            .await
            .unwrap()
            .local_network_access,
        edited
    );
    // A present legacy expected token has ON semantics, and cannot overwrite OFF.
    let mut wire = mullvad_management_interface::types::LocalNetworkAccess::from(&edited);
    wire.skip_local_rules_for_excluded_apps = None;
    let expected = mullvad_management_interface::types::local_policy_for_compare_set(wire).unwrap();
    assert!(
        settings
            .set_local_network_access(LocalNetworkAccess::default(), Some(expected))
            .await
            .is_err()
    );
    assert_eq!(settings.local_network_access, edited);
    // The existing unconditional RPC remains unconditional.
    assert!(
        settings
            .set_local_network_access(LocalNetworkAccess::default(), None)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn accepted_policy_is_deduplicated_before_persistence_without_losing_conditions() {
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    let mut repeated = policy();
    let rule = &mut repeated.rules[0];
    rule.cidrs.push(rule.cidrs[0]);
    rule.ssid_ids.push(rule.ssid_ids[0].clone());
    settings
        .set_local_network_access(repeated, None)
        .await
        .unwrap();
    assert_eq!(settings.local_network_access, policy());
    assert_eq!(
        SettingsPersister::load_from_file(&settings.path)
            .await
            .unwrap()
            .local_network_access,
        policy()
    );
}

#[tokio::test]
async fn split_dns_normalized_disk_readback_precedes_notification_and_shares_exact_local_cas() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    let path = settings.path.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let observer = count.clone();
    settings.register_change_listener(move |updated| {
        let disk = SettingsPersister::load_from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(disk, *updated);
        assert_eq!(
            disk.local_network_access.split_dns.suffixes,
            ["home.", "nas.home."]
        );
        observer.fetch_add(1, Ordering::SeqCst);
    });
    let old = settings.local_network_access.clone();
    assert!(
        settings
            .set_local_network_access(dns_policy(), Some(old.clone()))
            .await
            .unwrap()
    );
    let normalized = settings.local_network_access.clone();
    assert_eq!(normalized.split_dns.suffixes, ["home.", "nas.home."]);
    assert_eq!(normalized.rules, policy().rules);
    assert!(!normalized.skip_local_rules_for_excluded_apps);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        !settings
            .set_local_network_access(dns_policy(), Some(normalized.clone()))
            .await
            .unwrap()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let disk = std::fs::read(&settings.path).unwrap();
    for field in 0..5 {
        let mut stale = normalized.clone();
        match field {
            0 => stale = old.clone(),
            1 => stale.split_dns.suffixes.reverse(),
            2 => stale.split_dns.enabled = false,
            3 => stale.split_dns.home_resolver = Some("192.168.240.11".parse().unwrap()),
            _ => stale.split_dns.local_rule_id = None,
        }
        let mut toggle = normalized.clone();
        toggle.skip_local_rules_for_excluded_apps = true;
        assert!(
            settings
                .set_local_network_access(toggle, Some(stale))
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&settings.path).unwrap(), disk);
    }
    let mut toggle = normalized.clone();
    toggle.skip_local_rules_for_excluded_apps = true;
    settings
        .set_local_network_access(toggle.clone(), Some(normalized.clone()))
        .await
        .unwrap();
    let mut rule_edit = normalized.clone();
    rule_edit.rules[0].name = "concurrent edit".into();
    assert!(
        settings
            .set_local_network_access(rule_edit, Some(normalized))
            .await
            .is_err()
    );
    assert_eq!(
        SettingsPersister::load_from_file(&settings.path)
            .await
            .unwrap()
            .local_network_access,
        toggle
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn split_dns_invalid_read_can_be_repaired_without_replacing_other_policy_fields() {
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    let mut invalid = dns_policy();
    invalid.split_dns.suffixes = vec!["*.private-domain-marker".into()];
    settings.settings.local_network_access = invalid.clone();
    SettingsPersister::save_inner(&settings.path, &settings.settings)
        .await
        .unwrap();
    let read = SettingsPersister::load_from_file(&settings.path)
        .await
        .unwrap();
    assert_eq!(read.local_network_access, invalid);
    assert!(read.local_network_access.validate().is_err());
    let mut replacement = read.local_network_access.clone();
    replacement.split_dns.suffixes = vec!["home".into()];
    settings
        .set_local_network_access(replacement.clone(), Some(invalid))
        .await
        .unwrap();
    replacement.normalize().unwrap();
    assert_eq!(
        SettingsPersister::load_from_file(&settings.path)
            .await
            .unwrap()
            .local_network_access,
        replacement
    );
    assert_eq!(replacement.rules, policy().rules);
    assert!(!replacement.skip_local_rules_for_excluded_apps);
    assert!(!format!("{:?}", settings.to_settings()).contains("private-domain-marker"));
}

#[tokio::test]
async fn split_dns_validation_and_failed_write_leave_disk_memory_and_notifications_unchanged() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let mut settings = scratch.settings();
    settings
        .set_local_network_access(dns_policy(), None)
        .await
        .unwrap();
    let before = settings.to_settings();
    let path = settings.path.clone();
    let disk = std::fs::read(&path).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observer = count.clone();
    settings.register_change_listener(move |_| {
        observer.fetch_add(1, Ordering::SeqCst);
    });
    for index in 0..4 {
        let mut invalid = before.local_network_access.clone();
        match index {
            0 => invalid.split_dns.suffixes = vec!["*.home".into()],
            1 => invalid.split_dns.home_resolver = None,
            2 => invalid.split_dns.local_rule_id = Some(Default::default()),
            _ => invalid.rules[0].cidrs.clear(),
        }
        assert!(
            settings
                .set_local_network_access(invalid, None)
                .await
                .is_err()
        );
        assert_eq!(settings.to_settings(), before);
        assert_eq!(std::fs::read(&path).unwrap(), disk);
    }
    let forbidden = scratch.0.join("write-blocker");
    std::fs::create_dir(&forbidden).unwrap();
    settings.path = forbidden;
    let mut changed = before.local_network_access.clone();
    changed.split_dns.enabled = false;
    assert!(
        settings
            .set_local_network_access(changed, None)
            .await
            .is_err()
    );
    assert_eq!(settings.to_settings(), before);
    assert_eq!(std::fs::read(path).unwrap(), disk);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn split_dns_reset_preserves_complete_and_incomplete_drafts_only_with_whole_policy_key() {
    for mut configured in [dns_policy(), policy()] {
        if !configured.split_dns.enabled {
            configured.split_dns.local_rule_id = Some(Default::default());
            configured.split_dns.suffixes = vec![".HOME.".into(), "home".into()];
        }
        let mut settings = persister(PathBuf::new());
        settings.settings.local_network_access = configured.clone();
        settings
            .reset(SettingsKeyList {
                keys: vec![SettingsKey::LocalNetworkAccess],
            })
            .await
            .unwrap();
        assert_eq!(settings.local_network_access, configured);
        assert!(
            !settings
                .local_network_access
                .skip_local_rules_for_excluded_apps
        );
        settings.reset(SettingsKeyList::default()).await.unwrap();
        assert_eq!(settings.local_network_access, LocalNetworkAccess::default());
    }
    // Like the inherited reset test, cfg(test) deliberately skips its disk save.
}
