package net.mullvad.mullvadvpn.test.publicdns

import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory

class PublicDnsWireTest {
    @TestFactory
    fun `should audit independent Java DNS vectors`(): List<DynamicTest> =
        PublicDnsWireVectors.cases().map { (name, vector) ->
            DynamicTest.dynamicTest(name, vector::run)
        }
}
