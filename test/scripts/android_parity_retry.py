"""Cause-attributed initial Android parity retries, using saved evidence only.

The recognized cause is upstream 8fcbcd553e's ephemeral-peer handshake timeout.
Other causes stay unexplained until their upstream path is independently proved.
There is no retry-count allowance and no relaxation after the first Connected.
"""

import re


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _endpoint(text, native=False):
    pattern = (
        r"endpoint: Endpoint \{ address: ([^,]+),"
        if native
        else r"tunnel_endpoint=TunnelEndpoint\{address=([^,}]+)"
    )
    match = re.search(pattern, text.replace("\\", ""))
    _require(match is not None, "Missing relay endpoint")
    return match[1]


def _one(rows, pattern, name):
    matches = [(i, row, re.search(pattern, row["message"])) for i, row in enumerate(rows)]
    matches = [item for item in matches if item[2]]
    _require(len(matches) == 1, "Missing or duplicate " + name)
    return matches[0]


def initial_retry_contract(events, native, expected_lifecycle):
    """Validate every initial retry's cause, then the exact remaining lifecycle.

    Inputs are the ordered management event dictionaries and the saved native
    log text. Return the original lifecycle and the attributed cycles. A cause
    must occur in that attempt's same-process interval, not merely somewhere in
    the file. This function performs no I/O and sends no traffic.
    """
    _require([e["index"] for e in events] == list(range(len(events))), "Event indices")
    _require(all(a["time_ns"] <= b["time_ns"] for a, b in zip(events, events[1:])), "Event clocks")
    transitions = []
    previous = "Disconnected"
    for event in events:
        match = re.search(r"state=(\w+)\(", event["state"])
        _require(match is not None, "Missing management state")
        state = match[1]
        if state != previous:
            transitions.append((state, event))
        previous = state
    names = [state for state, _ in transitions]
    _require("Connected" in names and names[0] == "Connecting", "Initial connection missing")
    connected = names.index("Connected")
    _require(connected % 2 == 1, "Incomplete initial reconnect cycle")
    _require(names[:connected] == ["Connecting", "Disconnecting"] * (connected // 2) + ["Connecting"], "Unexpected initial lifecycle")
    retries = connected // 2
    _require(names[2 * retries:] == expected_lifecycle, "Unexpected post-retry lifecycle")
    if not retries:
        return {"lifecycle": names, "retries": []}

    rows = []
    for number, line in enumerate(native.splitlines(), 1):
        match = re.match(r"^\d\d-\d\d (\d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\d+)\s+\w mullvad-daemon: (.*)$", line)
        if match:
            rows.append({"line": number, "time": match[1], "pid": int(match[2]), "tid": int(match[3]), "message": match[4]})
    first_endpoint = _endpoint(transitions[0][1]["state"])
    starts = [(i, row) for i, row in enumerate(rows) if "mullvad_daemon: New tunnel state: Connecting {" in row["message"] and _endpoint(row["message"], True) == first_endpoint]
    _require(len(starts) == 1, "Ambiguous initial native attempt")
    start, first = starts[0]
    pid = first["pid"]
    owned = [row for row in rows[start:] if row["pid"] == pid]
    native_states = []
    for i, row in enumerate(owned):
        match = re.search(r"^mullvad_daemon: New tunnel state: (Connecting|Connected|Disconnecting|Disconnected|Error)\b", row["message"])
        if match:
            native_states.append((match[1], i, row))
            if match[1] == "Connected":
                break
    _require([state for state, _, _ in native_states] == names[:connected + 1], "Native/management initial states differ")
    for (state, _, row), (_, event) in zip(native_states, transitions):
        if state in ("Connecting", "Connected"):
            _require(_endpoint(row["message"], True) == _endpoint(event["state"]), "Native/management relay differs")
        else:
            _require(row["message"].endswith("Disconnecting(Reconnect)") and "after_disconnect=RECONNECT" in event["state"], "Not a reconnect action")

    proofs = []
    for attempt in range(retries):
        _, begin, begin_row = native_states[2 * attempt]
        _, end, end_row = native_states[2 * attempt + 1]
        window = owned[begin:end]
        relay = _endpoint(begin_row["message"], True)
        for row in window:
            message = row["message"]
            _require(not re.search(r"mullvad_daemon::management_interface: (?:connect_tunnel|disconnect_tunnel|reconnect_tunnel|set_|update_|reset_)", message), "Conflicting management command")
            _require("Writing settings to" not in message, "Conflicting settings change")
            _require(not re.search(r"offline state.*Offline|Ephemeral peer negotiation cancelled|router-target|attachment: Some\(", message), "Conflicting offline/cancellation/carrier cause")
        negotiation = _one(window, r"^talpid_tunnel_config_client::negotiation: Negotiating ephemeral peer with the ingress relay (\S+) \(pq=true, daita=false\)$", "negotiation")
        _require(negotiation[2][1] == relay, "Timeout belongs to another relay")
        absent = _one(window, r"^talpid_tunnel_config_client::negotiation: No handshake with the relay within (\d+)s$", "missing-handshake cause")
        timeout = _one(window, r"^talpid_wireguard::ephemeral: Timeout while negotiating ephemeral peers \(retry (\d+), timeout (\d+)s, handshake timeout (\d+)s, PQ=true, DAITA=false\)$", "ephemeral timeout")
        handshake = min(15, 4 * 2 ** min(attempt, 2))
        exchange = min(48, 8 * 2 ** min(attempt, 3))
        _require(tuple(map(int, timeout[2].groups())) == (attempt, exchange, handshake), "Wrong upstream retry/backoff")
        _require(int(absent[2][1]) == handshake, "Handshake deadline differs")
        closed = _one(window, r"^talpid_wireguard: Tunnel was closed: Ok\($", "monitor close")
        reason = _one(window, r"^\s*EphemeralPeerNegotiationTimeout,$", "monitor close reason")
        _require(closed[1]["tid"] == reason[1]["tid"], "Close reason belongs to another monitor")
        tsm = _one(window, r"^talpid_core::tunnel_state_machine::connecting_state: WireGuard tunnel timed out$", "TSM timeout")
        channel = _one(window, r"^talpid_core::tunnel_state_machine::connecting_state: The tunnel disconnected unexpectedly$", "TSM reconnect event")
        block = _one(window, r"^talpid_core::tunnel_state_machine::connecting_state: Tunnel monitor exited with block reason: None$", "nonblocking monitor exit")
        _require(negotiation[0] < absent[0] < timeout[0] < closed[0] < reason[0] < tsm[0], "Reordered cause chain")
        _require(reason[0] < channel[0] and reason[0] < block[0], "Reconnect precedes its cause")
        proofs.append({"attempt": attempt, "pid": pid, "relay": relay, "cause": "upstream-ephemeral-handshake-timeout", "handshake_seconds": handshake, "exchange_seconds": exchange, "connecting_line": begin_row["line"], "disconnecting_line": end_row["line"], "cause_lines": [item[1]["line"] for item in (negotiation, absent, timeout, closed, reason, tsm, channel, block)]})
    return {"lifecycle": names, "retries": proofs}
