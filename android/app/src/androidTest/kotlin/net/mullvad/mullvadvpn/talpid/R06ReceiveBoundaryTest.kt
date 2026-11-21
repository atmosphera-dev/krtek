package net.mullvad.mullvadvpn.talpid

import android.app.Instrumentation
import android.os.Bundle
import android.os.SystemClock
import java.io.File
import org.json.JSONObject

/** Explicit test-only observation latency before the unchanged Java socket is created. */
internal object R06ReceiveBoundaryTest {
    class Observer(private val instrumentation: Instrumentation, args: Bundle) {
        private val enabled = args.getString("krtek_r06_receive_boundary", "false") == "true"
        private val token = args.getString("krtek_capture_token", "")

        fun beforeConnect(index: Int, transport: String, expect: String, nonce: String) {
            if (!enabled || transport != "tcp" || expect != "reply") return
            require(token.matches(Regex("[a-zA-Z0-9-]+")))
            val root = File(instrumentation.targetContext.filesDir, "krtek-r06/$token")
            check(root.exists() || root.mkdirs())
            val acknowledgement = File(root, "receive-$index.ack")
            check(!acknowledgement.exists()) { "Fresh receive-boundary ACK required" }
            val started = SystemClock.elapsedRealtimeNanos()
            val request =
                JSONObject()
                    .put("token", token)
                    .put("index", index)
                    .put("nonce", nonce)
                    .put("consumer_uid", instrumentation.context.applicationInfo.uid)
                    .put("elapsed_ns", started)
            instrumentation.sendStatus(
                0,
                Bundle().apply {
                    putString("krtek_r06_pre_connect", request.toString())
                },
            )
            val deadline = SystemClock.elapsedRealtime() + 30_000
            while (!acknowledgement.exists()) {
                check(SystemClock.elapsedRealtime() < deadline) { "Receive-boundary ACK deadline" }
                SystemClock.sleep(20)
            }
            val ack =
                JSONObject(
                    acknowledgement.reader(Charsets.UTF_8).use {
                        LocalContinuityWindows.readBounded(it)
                    }
                )
            check(
                ack.getString("token") == token &&
                    ack.getInt("index") == index &&
                    ack.getString("nonce") == nonce &&
                    ack.getBoolean("snapshot_sealed")
            ) {
                "Receive-boundary ACK identity differs"
            }
            instrumentation.sendStatus(
                0,
                Bundle().apply {
                    putString(
                        "krtek_r06_pre_connect_end",
                        request
                            .put("end_elapsed_ns", SystemClock.elapsedRealtimeNanos())
                            .put(
                                "timing_effect",
                                "Read-only snapshot before original socket creation; no retry",
                            )
                            .toString(),
                    )
                },
            )
        }
    }
}
