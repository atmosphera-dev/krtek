package net.mullvad.mullvadvpn.talpid

import java.util.concurrent.CountDownLatch
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ExternalUiActionCompletionTest {
    @Test
    fun queuedComposeWritesCompleteBeforeBlockingObservation() {
        for (body in listOf("  B7 \u4e2d\u6587 & original  ", "complete body & ".repeat(500))) {
            val scheduler = TestCoroutineScheduler()
            val scope = CoroutineScope(StandardTestDispatcher(scheduler))
            val changed = CountDownLatch(1)
            val order = mutableListOf<String>()
            var clipboard: String? = null
            var writes = 0
            try {
                scope.launch {
                    writes++
                    clipboard = body
                    order.add("write")
                    changed.countDown()
                }
                // The actual native clipboard write is still queued after Android-only idle.
                assertEquals(null, clipboard)
                assertEquals(1L, changed.count)
                ExternalUiActionCompletion.settle(
                    androidIdle = { order.add("android") },
                    composeIdle = {
                        order.add("compose")
                        scheduler.runCurrent()
                    },
                )
                assertEquals(listOf("android", "compose", "write"), order)
                assertEquals(0L, changed.count)
                assertEquals(body, clipboard)
                assertEquals(1, writes)
            } finally {
                scope.cancel()
            }
        }
    }

    @Test
    fun missingWriteNotificationOrCompleteBodyStillFails() {
        for (fault in listOf("no-write", "no-notification", "changed-body")) {
            val scheduler = TestCoroutineScheduler()
            val scope = CoroutineScope(StandardTestDispatcher(scheduler))
            val changed = CountDownLatch(1)
            val body = "full reviewed body with leading and trailing space "
            var clipboard: String? = null
            try {
                if (fault != "no-write")
                    scope.launch {
                        clipboard = if (fault == "changed-body") body.trim() else body
                        if (fault != "no-notification") changed.countDown()
                    }
                ExternalUiActionCompletion.settle({}, scheduler::runCurrent)
                assertFailsWith<AssertionError> {
                    assertEquals(0L, changed.count)
                    assertEquals(body, clipboard)
                }
            } finally {
                scope.cancel()
            }
        }
    }

    @Test
    fun completionFailuresPropagateWithoutRepeatingBarriers() {
        for (failure in listOf("android", "compose")) {
            val order = mutableListOf<String>()
            assertFailsWith<IllegalStateException> {
                ExternalUiActionCompletion.settle(
                    androidIdle = {
                        order.add("android")
                        if (failure == "android") error("Android completion failed")
                    },
                    composeIdle = {
                        order.add("compose")
                        error("Compose completion failed")
                    },
                )
            }
            assertEquals(
                if (failure == "android") listOf("android") else listOf("android", "compose"),
                order,
            )
        }
    }

    @Test
    fun eachExternalActionHasItsOwnCompletion() {
        val scheduler = TestCoroutineScheduler()
        val scope = CoroutineScope(StandardTestDispatcher(scheduler))
        val observed = mutableListOf<String>()
        var androidIdles = 0
        var composeIdles = 0
        try {
            for (action in listOf("clipboard", "blocked-browser-intent")) {
                scope.launch { observed.add(action) }
                ExternalUiActionCompletion.settle(
                    androidIdle = { androidIdles++ },
                    composeIdle = {
                        composeIdles++
                        scheduler.runCurrent()
                    },
                )
                assertEquals(action, observed.last())
            }
            assertEquals(listOf("clipboard", "blocked-browser-intent"), observed)
            assertEquals(2, androidIdles)
            assertEquals(2, composeIdles)
        } finally {
            scope.cancel()
        }
    }
}
