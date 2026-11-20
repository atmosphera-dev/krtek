package net.mullvad.mullvadvpn.talpid

import android.app.Instrumentation
import android.os.Bundle
import android.os.SystemClock
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID
import org.json.JSONObject

/** Test-only failure barrier. It delays restoration, never retries the failed socket. */
internal object R06FirstFailureCustody {
    class Custody(
        private val instrumentation: Instrumentation,
        args: Bundle,
    ) {
        private val token = checkNotNull(args.getString("krtek_capture_token"))
        private val root: File
        private var currentStage = args.getString("class", "setup") ?: "setup"
        private var firstFailure = false
        private var custodyFailure: Throwable? = null
        val ledger = R06FailureLedger.Ledger { phase, error -> persistFailure(phase, error) }

        init {
            require(token.matches(Regex("[a-zA-Z0-9-]+")))
            root = File(instrumentation.targetContext.filesDir, "krtek-r06/$token")
            check(!root.exists()) { "Fresh r06 token required" }
            check(root.mkdirs())
        }

        private fun report(key: String, value: String) {
            instrumentation.sendStatus(0, Bundle().apply { putString("krtek_r06_$key", value) })
        }

        fun stage(stage: String) {
            currentStage = stage
            report(
                "stage",
                JSONObject()
                    .put("stage", stage)
                    .put("elapsed_ns", SystemClock.elapsedRealtimeNanos())
                    .toString(),
            )
        }

        fun completed(phase: String) {
            report("phase", JSONObject().put("phase", phase).put("result", "PASS").toString())
        }

        fun recordFailure(phase: String, error: Throwable) {
            ledger.record(phase, error)
            custodyFailure?.let { ledger.record("first-failure-custody", it) }
        }

        private fun persistFailure(phase: String, error: Throwable) {
            val value =
                JSONObject()
                    .put("phase", phase)
                    .put("stage", currentStage)
                    .put("elapsed_ns", SystemClock.elapsedRealtimeNanos())
                    .put("error_class", error.javaClass.name)
                    .put("message", error.message?.take(512))
            FileOutputStream(File(root, "failures.jsonl"), true).use { output ->
                output.write((value.toString() + "\n").toByteArray(Charsets.UTF_8))
                output.fd.sync()
            }
            report("phase", value.put("result", "FAIL").toString())
        }

        fun observe(transport: String, result: Bundle) {
            if (firstFailure || transport != "tcp" || result.getString("outcome") != "failed")
                return
            try {
                val raw = checkNotNull(result.getString("socket_report"))
                val parsed = JSONObject(raw)
                val events = parsed.getJSONArray("events")
                val failedConnect =
                    (0 until events.length()).any { index ->
                        val event = events.getJSONObject(index)
                        event.optString("operation") == "connect" &&
                            event.optString("phase") == "failed"
                    }
                if (failedConnect)
                    checkpoint("socket_report", parsed, result.getString("request_id"))
            } catch (error: Throwable) {
                // The caller's existing result assertion still runs and remains
                // primary. ACK/storage/decoder failures are retained separately.
                custodyFailure = error
            }
        }

        fun observeSession(session: JSONObject) {
            if (firstFailure || session.optString("failure").isEmpty()) return
            try {
                checkpoint("session_report", session, null)
            } catch (error: Throwable) {
                custodyFailure = error
            }
        }

        private fun checkpoint(kind: String, payload: JSONObject, requestId: String?) {
            firstFailure = true
            val nonce = UUID.randomUUID().toString()
            val started = SystemClock.elapsedRealtimeNanos()
            val snapshot =
                JSONObject()
                    .put("token", token)
                    .put("nonce", nonce)
                    .put("stage", currentStage)
                    .put("request_id", requestId)
                    .put("observation_kind", kind)
                    .put(kind, payload)
                    .put("barrier_started_elapsed_ns", started)
                    .put(
                        "timing_effect",
                        "Test-only pause after original failure is reported and before test restoration; no retry",
                    )
            val snapshotFile = File(root, "first-failure.json")
            check(snapshotFile.createNewFile())
            val bytes = snapshot.toString().toByteArray(Charsets.UTF_8)
            FileOutputStream(snapshotFile).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            val digest =
                MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
                    "%02x".format(it)
                }
            report(
                "failure_barrier",
                JSONObject()
                    .put("token", token)
                    .put("nonce", nonce)
                    .put("stage", currentStage)
                    .put("path", snapshotFile.absolutePath)
                    .put("size", bytes.size)
                    .put("sha256", digest)
                    .put("ack_path", File(root, "first-failure.ack").absolutePath)
                    .put("elapsed_ns", started)
                    .toString(),
            )
            val acknowledgement = File(root, "first-failure.ack")
            val deadline = SystemClock.elapsedRealtime() + 120_000
            try {
                while (!acknowledgement.exists()) {
                    check(SystemClock.elapsedRealtime() < deadline) {
                        "First-failure checkpoint ACK deadline"
                    }
                    SystemClock.sleep(20)
                }
                val ackText =
                    acknowledgement.reader(Charsets.UTF_8).use {
                        LocalContinuityWindows.readBounded(it)
                    }
                val ack = JSONObject(ackText)
                check(
                    ack.getString("token") == token &&
                        ack.getString("nonce") == nonce &&
                        ack.getString("stage") == currentStage &&
                        ack.getString("snapshot_sha256") == digest &&
                        ack.getBoolean("checkpoint_sealed")
                ) {
                    "First-failure ACK does not seal this checkpoint"
                }
            } finally {
                // This receipt does not say the external checkpoint succeeded. The
                // raw failed snapshot is immutable even on ACK timeout/mismatch.
                report(
                    "failure_barrier_end",
                    JSONObject()
                        .put("stage", currentStage)
                        .put("elapsed_ns", SystemClock.elapsedRealtimeNanos())
                        .put("barrier_started_elapsed_ns", started)
                        .toString(),
                )
            }
        }
    }
}
