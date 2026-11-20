package net.mullvad.mullvadvpn.lib.grpc.mapper

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import mullvad_daemon.management_interface.LocalNetworkAccess
import mullvad_daemon.management_interface.LocalNetworkPolicyUpdate
import mullvad_daemon.management_interface.SplitDnsPolicy
import org.junit.jupiter.api.Test

class SplitDnsPolicyMapperTest {
    @Test
    fun `should read absent and default nested DNS off without dropping A fields`() {
        for (dns in listOf(null, SplitDnsPolicy())) {
            val wire =
                LocalNetworkAccess(
                    enabled = true,
                    skip_local_rules_for_excluded_apps = false,
                    split_dns = dns,
                )
            val read = wire.toDomain()
            assertEquals(net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy(), read.splitDns)
            assertFalse(read.skipLocalRulesForExcludedApps)
            assertEquals(wire.copy(split_dns = null), read.asExpected())
            assertEquals(read, read.fromDomain().toDomain())
        }
    }

    @Test
    fun `should retain raw represented DNS through reads expected tokens and protobuf`() {
        for (resolver in listOf("10.77.10.53", "fd71:7274:656b:10::53", "::ffff:192.0.2.1")) {
            val wire =
                LocalNetworkAccess(
                    enabled = true,
                    skip_local_rules_for_excluded_apps = false,
                    split_dns =
                        SplitDnsPolicy(
                            enabled = true,
                            suffixes = listOf(".HOME.", "home", "*.private-marker"),
                            home_resolver = resolver,
                            local_rule_id = "00000000-0000-0000-0000-000000000013",
                        ),
                )
            val decoded = LocalNetworkAccess.ADAPTER.decode(LocalNetworkAccess.ADAPTER.encode(wire))
            val read = decoded.toDomain()
            assertEquals(checkNotNull(wire.split_dns).suffixes, read.splitDns.suffixes)
            assertFalse(read.skipLocalRulesForExcludedApps)
            val expected = read.asExpected()
            assertEquals(read, expected.toDomain())
            assertEquals(
                expected,
                LocalNetworkAccess.ADAPTER.decode(LocalNetworkAccess.ADAPTER.encode(expected)),
            )
            val update =
                LocalNetworkPolicyUpdate(policy = LocalNetworkAccess(), expected = expected)
            assertEquals(
                update,
                LocalNetworkPolicyUpdate.ADAPTER.decode(
                    LocalNetworkPolicyUpdate.ADAPTER.encode(update)
                ),
            )
        }
    }

    @Test
    fun `should reject unrepresentable resolvers and rule IDs without echoing payloads`() {
        for (dns in
            listOf(
                SplitDnsPolicy(home_resolver = "private-marker.invalid"),
                SplitDnsPolicy(home_resolver = ""),
                SplitDnsPolicy(local_rule_id = "private-marker"),
                SplitDnsPolicy(local_rule_id = "1-1-1-1-1"),
            )) {
            val error =
                assertFailsWith<IllegalArgumentException> {
                    LocalNetworkAccess(split_dns = dns).toDomain()
                }
            assertFalse(error.toString().contains("private-marker"))
        }
    }

    @Test
    fun `should save incomplete disabled DNS but refuse invalid suffix replacements`() {
        val incomplete =
            LocalNetworkAccess(
                split_dns = SplitDnsPolicy(local_rule_id = "00000000-0000-0000-0000-000000000013")
            )
        assertEquals(
            incomplete.copy(skip_local_rules_for_excluded_apps = true),
            incomplete.toDomain().fromDomain(),
        )
        val invalid =
            incomplete.copy(
                split_dns =
                    checkNotNull(incomplete.split_dns).copy(suffixes = listOf("*.private-marker"))
            )
        val read = invalid.toDomain()
        assertEquals(invalid.copy(skip_local_rules_for_excluded_apps = true), read.asExpected())
        assertFailsWith<IllegalArgumentException> { read.fromDomain() }
    }
}
