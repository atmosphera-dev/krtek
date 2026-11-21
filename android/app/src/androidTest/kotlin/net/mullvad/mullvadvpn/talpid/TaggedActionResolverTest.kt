package net.mullvad.mullvadvpn.talpid

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TaggedActionResolverTest {
    private class Node(
        val id: Int,
        val click: Boolean = false,
        val toggle: Boolean = false,
        val enabled: Boolean = true,
        val parent: Node? = null,
    ) {
        val children = mutableListOf<Node>()

        init {
            parent?.children?.add(this)
        }

        fun describe() =
            "id=$id, enabled=$enabled, OnClick=$click, Toggleable=$toggle, bounds=(0,0,100,40)"
    }

    private fun resolve(node: Node) =
        TaggedActionResolver.resolve(
            node,
            { it.children },
            { it.parent },
            { it.click },
            { it.toggle },
            { it.describe() },
        )

    @Test
    fun taggedRowWinsOverItsNestedSwitch() {
        val row = Node(1, click = true)
        Node(2, click = true, toggle = true, parent = row)
        assertSame(row, resolve(row))
    }

    @Test
    fun navigationWrapperResolvesItsSingleNestedClickOwner() {
        val wrapper = Node(1)
        val layout = Node(2, parent = wrapper)
        val row = Node(3, click = true, parent = layout)
        assertSame(row, resolve(wrapper))
    }

    @Test
    fun toggleableDescendantIsAnActionCandidate() {
        val wrapper = Node(1)
        val toggle = Node(2, toggle = true, parent = wrapper)
        assertSame(toggle, resolve(wrapper))
    }

    @Test
    fun taggedContentUsesNearestClickableAncestorNotOuterRow() {
        val outer = Node(1, click = true)
        val button = Node(2, click = true, parent = outer)
        val toggleOnly = Node(3, toggle = true, parent = button)
        val content = Node(4, parent = toggleOnly)
        assertSame(button, resolve(content))
    }

    @Test
    fun multipleDescendantsFailEvenWithClickableAncestor() {
        val outer = Node(1, click = true)
        val wrapper = Node(2, parent = outer)
        val first = Node(3, click = true, parent = wrapper)
        val second = Node(4, toggle = true, parent = wrapper)
        val failure = assertThrows(AssertionError::class.java) { resolve(wrapper) }
        for (node in listOf(wrapper, first, second)) {
            assertTrue(failure.message!!.contains(node.describe()))
        }
    }

    @Test
    fun missingActionFailsWithNodeSemanticsAndBounds() {
        val node = Node(1)
        val failure = assertThrows(AssertionError::class.java) { resolve(node) }
        assertEquals("Missing tagged action: tagged=${node.describe()}", failure.message)
    }

    @Test
    fun disabledOwnerIsNotSkippedForAnotherAction() {
        val outer = Node(1, click = true)
        val button = Node(2, click = true, enabled = false, parent = outer)
        assertSame(button, resolve(button))
    }
}
