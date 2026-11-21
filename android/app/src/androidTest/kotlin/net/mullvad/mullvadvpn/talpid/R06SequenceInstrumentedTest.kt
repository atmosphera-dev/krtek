package net.mullvad.mullvadvpn.talpid

import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.PackageName
import net.mullvad.mullvadvpn.lib.repository.SplitTunnelingRepository
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin

/** Recoverable historical inner sequence, not the missing full 27-call manifest. */
class R06SequenceInstrumentedTest {
    @Test
    fun r06HistoricalSequence() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        val args = InstrumentationRegistry.getArguments()
        val trace = args.getString("trace", "off")
        require(trace in setOf("off", "boundaries"))
        val fixture = LocalNetworkDeliveryInstrumentedTest()
        val custody =
            checkNotNull(fixture.r06Custody) {
                "Historical campaign requires krtek_r06_custody=true"
            }
        fixture.report("r06_campaign_kind", "historical-inner-reconstruction")
        fixture.report("r06_trace", checkNotNull(trace))
        try {
            fixture.connectedCase(testTimeout = R06_SEQUENCE_TEST_TIMEOUT) {
                consumer,
                repository,
                connection,
                policy ->
                val original = checkNotNull(repository.settingsUpdates.value)
                val split =
                    (target.applicationContext as MullvadApplication)
                        .getKoin()
                        .get<SplitTunnelingRepository>()
                val excluded =
                    PackageName(args.getString("krtek_exclusion_package", "com.android.deskclock"))
                val excludedUid = target.packageManager.getApplicationInfo(excluded.value, 0).uid
                val consumerUid =
                    target.packageManager
                        .getApplicationInfo(instrumentation.context.packageName, 0)
                        .uid
                assertNotEquals(target.applicationInfo.uid, excludedUid)
                assertNotEquals(consumerUid, excludedUid)
                assertTrue(
                    PackageName(instrumentation.context.packageName) !in
                        original.splitTunnelSettings.excludedApps
                )
                assertTrue(excluded !in original.splitTunnelSettings.excludedApps)

                fun proof(
                    stage: String,
                    previous: String? = null,
                ): LocalNetworkDeliveryInstrumentedTest.AppliedCapture {
                    custody.stage(stage)
                    return fixture.connectedProof(consumer, repository, connection, previous)
                }
                fun nativeControl(
                    stage: String
                ): LocalNetworkDeliveryInstrumentedTest.AppliedCapture {
                    custody.stage(stage)
                    return fixture.withNativeControl(consumer, repository, connection, policy)
                }

                // As in the historical method, initial proof precedes inner try/finally.
                val before = proof("initial-connected")
                custody.ledger.run(
                    body = {
                        custody.stage("add-covered-cidr")
                        val announced =
                            policy.copy(
                                rules =
                                    policy.rules.map {
                                        it.copy(
                                            cidrs =
                                                it.cidrs +
                                                    checkNotNull(
                                                        LocalCidr.parse("10.0.2.99/32").getOrNull()
                                                    )
                                        )
                                    }
                            )
                        fixture.setPolicy(repository, announced)
                        assertEquals(
                            before,
                            proof("added-covered-cidr"),
                            "Default-covered CIDRs reuse the entire capture",
                        )

                        custody.stage("replace-peer-rule-and-deny")
                        val withoutPeer =
                            policy.copy(
                                rules =
                                    policy.rules.map {
                                        it.copy(
                                            id = UUID.randomUUID(),
                                            cidrs =
                                                listOf(
                                                    checkNotNull(
                                                        LocalCidr.parse("10.0.2.99/32").getOrNull()
                                                    )
                                                ),
                                        )
                                    }
                            )
                        fixture.setPolicy(repository, withoutPeer)
                        assertEquals(
                            before,
                            fixture.appliedConfiguration(
                                withoutPeer,
                                ForwardingAvailability.Active,
                                "Connected",
                            ),
                        )
                        listOf("tcp", "udp").forEach {
                            fixture.probeSocket(consumer, it, "blocked")
                        }

                        // Deliberately NO later same-ID edit/revoke stage here.
                        custody.stage("add-new-peer-rule")
                        val previousRevision =
                            checkNotNull(repository.localNetworkStatus.value).revision
                        val newRule =
                            withoutPeer.copy(
                                rules =
                                    withoutPeer.rules +
                                        policy.rules.single().copy(id = UUID.randomUUID())
                            )
                        fixture.setPolicy(repository, newRule)
                        val status =
                            fixture.awaitState(
                                repository,
                                connection,
                                ForwardingAvailability.Active,
                                LocalRuleState.Forwarding,
                                "Connected",
                            )
                        assertTrue(
                            status.revision > previousRevision,
                            "A new rule row is published",
                        )
                        assertEquals(newRule.rules.map { it.id }, status.rules.map { it.id })
                        assertEquals(
                            before,
                            proof("new-peer-rule-authorized"),
                            "Newly authorized TCP/UDP delivery does not require a new capture",
                        )
                        fixture.report(
                            "new_rule_destination_delivered",
                            checkNotNull(args.getString("krtek_peer", "10.0.2.2")),
                        )
                        fixture.report(
                            "new_rule_status_revision",
                            "before=$previousRevision,after=${status.revision}",
                        )
                        fixture.report("covered_route_reuses_capture", true)

                        fixture.setPolicy(repository, policy)
                        val restoredRoutes = proof("restore-peer-routes")
                        assertEquals(
                            before,
                            restoredRoutes,
                            "Removing covered CIDRs retains capture identity",
                        )
                        custody.stage("flip-legacy-lan")
                        runBlocking {
                            assertTrue(
                                repository.setLocalNetworkSharing(!original.allowLan).isRight()
                            )
                            withTimeout(10_000) {
                                repository.settingsUpdates.first {
                                    it?.allowLan == !original.allowLan
                                }
                            }
                        }
                        val legacy = proof("legacy-lan-flipped", restoredRoutes.generation)
                        assertNotEquals(
                            restoredRoutes.routes,
                            legacy.routes,
                            "Legacy bypass changes the effective route set",
                        )
                        val legacyControl = nativeControl("first-local-off-on-native-control")
                        assertEquals(legacy.routes, legacyControl.routes)

                        custody.stage("restore-legacy-lan")
                        runBlocking {
                            assertTrue(
                                repository.setLocalNetworkSharing(original.allowLan).isRight()
                            )
                            withTimeout(10_000) {
                                repository.settingsUpdates.first {
                                    it?.allowLan == original.allowLan
                                }
                            }
                        }
                        val restoredLegacy = proof("legacy-lan-restored", legacyControl.generation)
                        assertEquals(before.routes, restoredLegacy.routes)
                        custody.stage("exclude-deskclock-then-enable-split")
                        runBlocking {
                            assertTrue(split.excludeApp(excluded).isRight())
                            assertTrue(split.enableSplitTunneling(true).isRight())
                            withTimeout(10_000) {
                                repository.settingsUpdates.first {
                                    it?.splitTunnelSettings?.let { settings ->
                                        settings.enabled && excluded in settings.excludedApps
                                    } == true
                                }
                            }
                        }
                        val exclusions = proof("deskclock-excluded", restoredLegacy.generation)
                        assertNotEquals(
                            restoredLegacy.uids,
                            exclusions.uids,
                            "Applied UID ranges must change",
                        )
                        assertTrue(fixture.uidIncluded(exclusions.uids, consumerUid))
                        assertTrue(!fixture.uidIncluded(exclusions.uids, excludedUid))
                        fixture.report("excluded_uid", excludedUid)
                        fixture.report("consumer_included", true)
                        val exclusionControl = nativeControl("second-local-off-on-native-control")
                        assertEquals(exclusions.uids, exclusionControl.uids)
                        custody.completed("body")
                    },
                    restoration = {
                        custody.stage("include-deskclock-restore-split-restore-lan")
                        runBlocking {
                            assertTrue(split.includeApp(excluded).isRight())
                            assertTrue(
                                split
                                    .enableSplitTunneling(original.splitTunnelSettings.enabled)
                                    .isRight()
                            )
                            assertTrue(
                                repository.setLocalNetworkSharing(original.allowLan).isRight()
                            )
                            withTimeout(10_000) {
                                repository.settingsUpdates.first {
                                    it?.allowLan == original.allowLan &&
                                        it.splitTunnelSettings == original.splitTunnelSettings
                                }
                            }
                        }
                        fixture.setPolicy(repository, policy)
                        // Historical final CP had NO generation floor. TCP is
                        // first, then UDP, then ordinary HTTPS. No retry.
                        val restored = proof("final-fresh-tcp-udp-https")
                        assertEquals(before.routes, restored.routes)
                        assertEquals(before.uids, restored.uids)
                        fixture.report("settings_restored", true)
                        custody.completed("settings-restoration")
                    },
                )
            }
            custody.completed("outer-fixture")
        } catch (error: Throwable) {
            custody.recordFailure("outer-fixture", error)
        }
        custody.ledger.throwIfFailed()
        fixture.report("r06_complete", true)
    }
}
