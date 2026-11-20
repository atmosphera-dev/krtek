package net.mullvad.mullvadvpn.test.publicdns;

import android.content.Context;
import android.os.Bundle;
import android.os.Process;
import androidx.test.platform.app.InstrumentationRegistry;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/** Self-targeted ordinary app UID; identical APKs are installed alongside Krtek and stock. */
public final class PublicDnsComparisonInstrumentedTest {
  @Test
  public void publicDnsExchange() throws Exception {
    Bundle args = InstrumentationRegistry.getArguments();
    int family = Integer.parseInt(args.getString("family", "0"));
    int size = Integer.parseInt(args.getString("request_bytes", "0"));
    String app = args.getString("app", "");
    String nonceHex = args.getString("nonce_hex", "");
    String peer = args.getString("peer", "");
    if (!(app.equals("krtek") || app.equals("stock"))
        || !(family == 4 || family == 6) || !(size == 76 || size == 4096)
        || !nonceHex.matches("[0-9a-f]{64}")
        || !peer.equals(family == 4 ? "1.1.1.1" : "2606:4700:4700::1111")) {
      throw new IllegalArgumentException("Frozen app/family/size/Cloudflare/nonce arguments required");
    }
    int id = Integer.parseInt(args.getString("dns_id", "-1"));
    byte[] nonce = new byte[32];
    for (int index = 0; index < nonce.length; index++) {
      nonce[index] = (byte) Integer.parseInt(nonceHex.substring(index * 2, index * 2 + 2), 16);
    }
    Context target = InstrumentationRegistry.getInstrumentation().getTargetContext();
    if (!target.getPackageName().equals("net.mullvad.mullvadvpn.test.publicdns")
        || target.getApplicationInfo().uid != Process.myUid()) {
      throw new IllegalStateException("Diagnostic must execute in its own ordinary target UID");
    }
    JSONObject report = PublicDnsExchange.run(target.getFilesDir(), family, peer,
        PublicDnsWire.query(id, nonce, size), null);
    report.put("comparison_app_label", app);
    Bundle result = new Bundle();
    result.putString("public_dns_report", report.toString());
    InstrumentationRegistry.getInstrumentation().sendStatus(0, result);
    // Timeout/TC/rcode are diagnostic outcomes, not DNS success assertions. Tool errors are not.
    if (report.getString("classification").equals("probe-error")
        || report.has("socket_close_errno") || !report.has("receipt")) {
      throw new IllegalStateException("Incomplete public-DNS probe: " + report);
    }
  }
}
