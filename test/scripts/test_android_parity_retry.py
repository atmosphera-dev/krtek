"""Offline contract tests; run inside the project builder VM."""

import copy
import unittest

from android_parity_retry import initial_retry_contract


def fixture(retries):
    events, lines = [], []

    def event(state, relay=None):
        detail = "after_disconnect=RECONNECT" if state == "Disconnecting" else "tunnel_endpoint=TunnelEndpoint{address=" + relay + "}"
        events.append({"index": len(events), "time_ns": len(events), "state": "TunnelState{state=" + state + "(" + detail + ")}"})

    def log(message):
        lines.append("01-01 00:00:00.000 42 43 D mullvad-daemon: " + message)

    for i in range(retries + 1):
        relay = "192.0.2.1:" + str(10000 + i)
        event("Connecting", relay)
        log("mullvad_daemon: New tunnel state: Connecting { endpoint: Endpoint { address: " + relay + ", } }")
        if i == retries:
            event("Connected", relay)
            log("mullvad_daemon: New tunnel state: Connected { endpoint: Endpoint { address: " + relay + ", } }")
            break
        handshake = min(15, 4 * 2 ** min(i, 2))
        exchange = min(48, 8 * 2 ** min(i, 3))
        log("talpid_tunnel_config_client::negotiation: Negotiating ephemeral peer with the ingress relay " + relay + " (pq=true, daita=false)")
        log(f"talpid_tunnel_config_client::negotiation: No handshake with the relay within {handshake}s")
        log(f"talpid_wireguard::ephemeral: Timeout while negotiating ephemeral peers (retry {i}, timeout {exchange}s, handshake timeout {handshake}s, PQ=true, DAITA=false)")
        log("talpid_wireguard: Tunnel was closed: Ok(")
        log("    EphemeralPeerNegotiationTimeout,")
        log("talpid_core::tunnel_state_machine::connecting_state: WireGuard tunnel timed out")
        log("talpid_core::tunnel_state_machine::connecting_state: The tunnel disconnected unexpectedly")
        log("talpid_core::tunnel_state_machine::connecting_state: Tunnel monitor exited with block reason: None")
        event("Disconnecting")
        log("mullvad_daemon: New tunnel state: Disconnecting(Reconnect)")
    return events, "\n".join(lines)


class InitialRetriesTest(unittest.TestCase):
    def check(self, events, native):
        return initial_retry_contract(events, native, ["Connecting", "Connected"])

    def test_zero_one_two_and_many_attributed_cycles(self):
        for count in (0, 1, 2, 20):
            with self.subTest(count=count):
                events, native = fixture(count)
                self.assertEqual(len(self.check(events, native)["retries"]), count)

    def test_unexplained_cycle_is_rejected(self):
        events, native = fixture(2)
        bad = "\n".join(line for line in native.splitlines() if "No handshake" not in line)
        with self.assertRaisesRegex(ValueError, "missing-handshake"):
            self.check(events, bad)

    def test_each_cycle_needs_its_own_cause(self):
        events, native = fixture(2)
        native = native.replace("No handshake with the relay within 8s", "unexplained second attempt")
        with self.assertRaises(ValueError):
            self.check(events, native)

    def test_wrong_pid_attempt_endpoint_and_conflicting_command_are_rejected(self):
        events, native = fixture(1)
        cases = [native.replace("42 43 D mullvad-daemon: talpid_wireguard::ephemeral", "99 43 D mullvad-daemon: talpid_wireguard::ephemeral"), native.replace("retry 0,", "retry 1,"), native.replace("ingress relay 192.0.2.1:10000", "ingress relay 192.0.2.2:10000"), native.replace("talpid_wireguard: Tunnel was closed", "mullvad_daemon::management_interface: reconnect_tunnel\n01-01 00:00:00.000 42 43 D mullvad-daemon: talpid_wireguard: Tunnel was closed")]
        for bad in cases:
            with self.subTest(native=bad), self.assertRaises(ValueError):
                self.check(events, bad)

    def test_post_connected_lifecycle_is_not_relaxed(self):
        events, native = fixture(2)
        bad = copy.deepcopy(events)
        bad.append({"index": len(bad), "time_ns": len(bad), "state": "TunnelState{state=Disconnecting(after_disconnect=RECONNECT)}"})
        with self.assertRaisesRegex(ValueError, "post-retry"):
            self.check(bad, native)

    def test_duplicate_reason_is_rejected(self):
        events, native = fixture(1)
        native = native.replace("    EphemeralPeerNegotiationTimeout,", "    EphemeralPeerNegotiationTimeout,\n01-01 00:00:00.000 42 43 D mullvad-daemon:     EphemeralPeerNegotiationTimeout,")
        with self.assertRaises(ValueError):
            self.check(events, native)


if __name__ == "__main__":
    unittest.main()
