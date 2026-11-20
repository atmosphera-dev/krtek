use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use futures::StreamExt;
use mullvad_management_interface::{MullvadProxyClient, client::DaemonEvent};
use mullvad_types::settings::local_network_access::status::LocalNetworkStatus;
use mullvad_types::{device::DeviceState, states::TunnelState};
use serde::Serialize;
use std::fmt::Debug;

use crate::format;

#[derive(Subcommand, Debug, PartialEq)]
pub enum Status {
    /// Listen for tunnel state changes
    Listen,
    /// Display Local network rule status, even without a configured policy
    Local,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Enable verbose output
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Enable debug output
    #[arg(long, short = 'd', conflicts_with_all = ["verbose", "json"])]
    debug: bool,

    /// Format output as JSON
    #[arg(long, short = 'j', conflicts_with_all = ["verbose", "debug"])]
    json: bool,
}

impl Status {
    pub async fn listen(
        mut event_stream: impl futures::Stream<
            Item = mullvad_management_interface::client::Result<DaemonEvent>,
        > + Unpin,
        args: StatusArgs,
        mut previous_tunnel_state: TunnelState,
        mut local_configured: bool,
    ) -> Result<()> {
        while let Some(event) = event_stream.next().await {
            match event? {
                DaemonEvent::TunnelState(new_state) => {
                    if !print_debug_or_json(&args, "New tunnel state", &new_state)? {
                        format::print_state(&new_state, Some(&previous_tunnel_state), args.verbose);
                        previous_tunnel_state = new_state;
                    }
                }
                DaemonEvent::Settings(settings) => {
                    local_configured = local_policy_configured(&settings.local_network_access);
                    print_debug_or_json(&args, "New settings", &SettingsStatus(&settings))?;
                }
                DaemonEvent::RelayList(relay_list) => {
                    print_debug_or_json(&args, "New relay list", &relay_list)?;
                }
                DaemonEvent::AppVersionInfo(app_version_info) => {
                    print_debug_or_json(&args, "New app version info", &app_version_info)?;
                }
                DaemonEvent::Device(device) => {
                    print_debug_or_json(&args, "Device event", &device)?;
                }
                DaemonEvent::RemoveDevice(device) => {
                    print_debug_or_json(&args, "Remove device event", &device)?;
                }
                DaemonEvent::NewAccessMethod(access_method) => {
                    print_debug_or_json(&args, "New access method", &access_method)?;
                }
                DaemonEvent::LocalNetworkStatus(status) => {
                    if local_network_summary_visible(&args, local_configured, false) {
                        print_local_network_summary(&status);
                    }
                }
                DaemonEvent::LocalNetworkStatusUnavailable => {}
                DaemonEvent::LeakDetected(leak) => {
                    #[derive(Debug, Serialize)]
                    struct Leak {
                        interface: String,
                        reachable: Vec<std::net::IpAddr>,
                    }
                    let leak = Leak {
                        interface: leak.interface,
                        reachable: leak.reachable_nodes,
                    };
                    print_debug_or_json(&args, "Leak detected", &leak)?;
                }
            }
        }
        Ok(())
    }
}

pub async fn handle(cmd: Option<Status>, args: StatusArgs) -> Result<()> {
    let mut rpc = MullvadProxyClient::new().await?;
    let state = rpc.get_tunnel_state().await?;
    let device = rpc.get_device().await?;

    print_account_logged_out(&state, &device);

    if !print_debug_or_json(&args, "New tunnel state", &state)? {
        format::print_state(&state, None, args.verbose);
    }

    let explicit_local = cmd == Some(Status::Local);
    let mut event_rpc = rpc.clone();
    let (event_stream, local_configured) = subscribe_then_snapshot(
        async {
            if cmd == Some(Status::Listen) {
                Ok(Some(event_rpc.events_listen().await?))
            } else {
                Ok(None)
            }
        },
        async {
            if args.json || args.debug {
                false
            } else {
                rpc.get_settings()
                    .await
                    .ok()
                    .is_some_and(|settings| local_policy_configured(&settings.local_network_access))
            }
        },
    )
    .await?;
    if let Some(status) = local_network_snapshot(
        &args,
        local_configured,
        explicit_local,
        rpc.get_local_network_status(),
    )
    .await
    {
        print_local_network_summary(&status);
    }

    if let Some(events) = event_stream {
        Status::listen(events, args, state, local_configured).await?;
    }
    Ok(())
}

/// Keep the event owner alive before sampling the state that its events update.
async fn subscribe_then_snapshot<S, T>(
    subscription: impl Future<Output = Result<S>>,
    snapshot: impl Future<Output = T>,
) -> Result<(S, T)> {
    let events = subscription.await?;
    let state = snapshot.await;
    Ok((events, state))
}

fn print_account_logged_out(state: &TunnelState, device: &DeviceState) {
    match state {
        TunnelState::Connecting { .. } | TunnelState::Connected { .. } | TunnelState::Error(_) => {
            match device {
                DeviceState::LoggedOut => {
                    println!("Warning: You are not logged in to an account.")
                }
                DeviceState::Revoked => println!("Warning: This device has been revoked."),
                DeviceState::LoggedIn(_) => (),
            }
        }
        TunnelState::Disconnected { .. } | TunnelState::Disconnecting(_) => (),
    }
}

fn local_policy_configured(policy: &mullvad_management_interface::types::LocalPolicyRead) -> bool {
    policy.policy.as_ref().map_or_else(
        || {
            policy
                .raw()
                .is_some_and(|raw| raw.enabled || !raw.rules.is_empty())
        },
        |policy| policy.enabled || !policy.rules.is_empty(),
    )
}

/// Formatting belongs to this consumer, not to the fallible RPC read boundary.
/// Valid settings keep the existing JSON/debug shape; unreadable Local is null,
/// never an apparently valid OFF policy. Raw Local protobufs are not formatted.
struct SettingsStatus<'a>(&'a mullvad_management_interface::types::SettingsRead);

impl Debug for SettingsStatus<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self.0, f)
    }
}

impl Serialize for SettingsStatus<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let settings = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("relay_settings", &settings.relay_settings)?;
        map.serialize_entry("obfuscation_settings", &settings.obfuscation_settings)?;
        map.serialize_entry("custom_lists", &settings.custom_lists)?;
        map.serialize_entry("api_access_methods", &settings.api_access_methods)?;
        map.serialize_entry("update_default_location", &settings.update_default_location)?;
        map.serialize_entry("allow_lan", &settings.allow_lan)?;
        map.serialize_entry(
            "local_network_access",
            &settings.local_network_access.policy,
        )?;
        map.serialize_entry("lockdown_mode", &settings.lockdown_mode)?;
        map.serialize_entry("auto_connect", &settings.auto_connect)?;
        map.serialize_entry("tunnel_options", &settings.tunnel_options)?;
        map.serialize_entry("relay_overrides", &settings.relay_overrides)?;
        map.serialize_entry("show_beta_releases", &settings.show_beta_releases)?;
        #[cfg(any(windows, target_os = "macos"))]
        map.serialize_entry("split_tunnel", &settings.split_tunnel)?;
        map.serialize_entry("settings_version", &settings.settings_version)?;
        map.serialize_entry("recents", &settings.recents)?;
        map.serialize_entry("rollout_threshold_seed", &settings.rollout_threshold_seed)?;
        map.end()
    }
}

fn local_network_summary_visible(args: &StatusArgs, configured: bool, explicit: bool) -> bool {
    !args.json && !args.debug && (configured || explicit)
}

async fn local_network_snapshot(
    args: &StatusArgs,
    configured: bool,
    explicit: bool,
    fetch: impl Future<Output = mullvad_management_interface::client::Result<LocalNetworkStatus>>,
) -> Option<LocalNetworkStatus> {
    if !local_network_summary_visible(args, configured, explicit) {
        return None;
    }
    match fetch.await {
        Ok(status) => Some(status),
        Err(error) => {
            eprintln!("Warning: Failed to fetch local network status: {error}");
            None
        }
    }
}

fn print_local_network_summary(status: &LocalNetworkStatus) {
    use mullvad_types::settings::local_network_access::status::{
        ForwardingAvailability, RuleState,
    };
    let forwarding = match status.forwarding {
        ForwardingAvailability::NotAvailable => "forwarding not available",
        ForwardingAvailability::Off => "delivery off",
        ForwardingAvailability::Active => "local rules ready",
        ForwardingAvailability::PausedWhileConnected => {
            "delivery paused while connecting or connected"
        }
        ForwardingAvailability::Failed => "delivery failed",
    };
    let ready = status
        .rules
        .iter()
        .filter(|rule| matches!(rule.state, RuleState::ConditionsMet | RuleState::Forwarding))
        .count();
    println!(
        "Local network: {forwarding}; {ready}/{} rule conditions met; observer {}",
        status.rules.len(),
        if status.observer_available {
            "available"
        } else {
            "unavailable"
        }
    );
}

/// Print the given value as debug or JSON output based on the provided arguments.
///
/// Returns `true` if the value was printed. Returns `false` otherwise, i.e. if
/// both `args.debug` and `args.json` are `false`.
fn print_debug_or_json<T: Debug + Serialize>(
    args: &StatusArgs,
    debug_message: &str,
    t: &T,
) -> Result<bool> {
    if args.debug {
        println!("{debug_message}: {t:#?}");
        Ok(true)
    } else if args.json {
        let json = serde_json::to_string(&t).context("Failed to format output as JSON")?;
        println!("{json}");
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mullvad_types::settings::local_network_access::LocalNetworkAccess;

    #[tokio::test]
    async fn local_snapshot_subscribes_first_and_retains_changes_during_the_read() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let subscribed = AtomicBool::new(false);
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        let (mut stream, configured) = subscribe_then_snapshot(
            async {
                subscribed.store(true, Ordering::SeqCst);
                Ok(receiver)
            },
            async {
                assert!(subscribed.load(Ordering::SeqCst));
                sender.unbounded_send(true).unwrap();
                false
            },
        )
        .await
        .unwrap();
        assert!(!configured);
        assert_eq!(stream.next().await, Some(true));
    }

    #[test]
    fn snapshot_and_events_share_text_mode_and_availability_visibility() {
        for json in [false, true] {
            for debug in [false, true] {
                for observer in [false, true] {
                    for rules in [false, true] {
                        let args = StatusArgs {
                            verbose: false,
                            debug,
                            json,
                        };
                        let mut status = LocalNetworkStatus::from_observation(
                            &LocalNetworkAccess::default(),
                            None,
                        );
                        status.observer_available = observer;
                        if rules {
                            use mullvad_types::settings::local_network_access::status::{
                                LocalRuleStatus, RuleState,
                            };
                            status.rules.push(LocalRuleStatus {
                                id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
                                state: RuleState::ConditionsMet,
                            });
                        }
                        assert_eq!(
                            local_network_summary_visible(&args, rules, false),
                            !json && !debug && rules
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn auxiliary_status_failure_is_nonfatal() {
        let args = StatusArgs {
            verbose: false,
            debug: false,
            json: false,
        };
        let result = local_network_snapshot(&args, true, false, async {
            Err(mullvad_management_interface::Error::MissingDaemonEvent)
        })
        .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn structured_modes_do_not_poll_the_auxiliary_rpc() {
        for (json, debug) in [(true, false), (false, true)] {
            let args = StatusArgs {
                verbose: false,
                debug,
                json,
            };
            assert!(
                local_network_snapshot(&args, true, true, async {
                    panic!("structured output must not fetch a text-only summary")
                })
                .await
                .is_none()
            );
        }
    }

    #[tokio::test]
    async fn local_status_visibility_requires_configuration_or_explicit_request() {
        let original = mullvad_types::settings::Settings::default();
        let original = mullvad_types::settings::Settings::try_from(
            mullvad_management_interface::types::Settings::from(&original),
        )
        .unwrap();
        let read = mullvad_management_interface::types::SettingsRead::try_from(
            mullvad_management_interface::types::Settings::from(&original),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&SettingsStatus(&read)).unwrap(),
            serde_json::to_string(&original).unwrap()
        );
        assert_eq!(format!("{read:#?}"), format!("{original:#?}"));
        for json in [false, true] {
            for debug in [false, true] {
                for configured in [false, true] {
                    for explicit in [false, true] {
                        let args = StatusArgs {
                            verbose: false,
                            debug,
                            json,
                        };
                        let called = std::cell::Cell::new(false);
                        let visible = !json && !debug && (configured || explicit);
                        let status = local_network_snapshot(&args, configured, explicit, async {
                            called.set(true);
                            Ok(LocalNetworkStatus::from_observation(
                                &LocalNetworkAccess::default(),
                                None,
                            ))
                        })
                        .await;
                        assert_eq!(called.get(), visible);
                        assert_eq!(status.is_some(), visible);
                    }
                }
            }
        }
        let mut wire = mullvad_management_interface::types::Settings::from(
            &mullvad_types::settings::Settings::default(),
        );
        wire.local_network_access = Some(mullvad_management_interface::types::LocalNetworkAccess {
            enabled: false,
            rules: vec![Default::default()],
            skip_local_rules_for_excluded_apps: None,
            split_dns: None,
        });
        let read = mullvad_management_interface::types::SettingsRead::try_from(wire).unwrap();
        assert!(local_policy_configured(&read.local_network_access));
        let output = serde_json::to_value(SettingsStatus(&read)).unwrap();
        assert!(output["local_network_access"].is_null());
    }
}
