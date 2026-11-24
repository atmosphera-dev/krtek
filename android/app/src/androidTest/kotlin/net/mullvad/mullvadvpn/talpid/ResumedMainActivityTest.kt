package net.mullvad.mullvadvpn.talpid

import android.content.Intent
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleCallback
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import net.mullvad.mullvadvpn.app.MainActivity

/** Owns a real activity without requiring a Compose or Espresso idle main loop. */
internal fun withResumedMainActivity(block: () -> Unit) {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    val target = instrumentation.targetContext
    val lifecycle = ActivityLifecycleMonitorRegistry.getInstance()
    val created = AtomicReference<MainActivity?>()
    val resumed = CountDownLatch(1)
    instrumentation.runOnMainSync {
        check(
            Stage.values().all { stage ->
                lifecycle.getActivitiesInStage(stage).none { it is MainActivity }
            }
        ) {
            "Preserve an existing activity instead of reusing or clearing it"
        }
    }
    val callback = ActivityLifecycleCallback { activity, stage ->
        if (activity is MainActivity && stage == Stage.PRE_ON_CREATE)
            created.compareAndSet(null, activity)
        if (stage == Stage.RESUMED && activity === created.get()) resumed.countDown()
    }
    lifecycle.addLifecycleCallback(callback)
    try {
        target.startActivity(
            Intent(target, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        check(resumed.await(10, TimeUnit.SECONDS)) {
            "Owned real activity did not reach resumed state"
        }
        block()
    } finally {
        lifecycle.removeLifecycleCallback(callback)
        created.get()?.let { activity -> instrumentation.runOnMainSync { activity.finish() } }
    }
}
