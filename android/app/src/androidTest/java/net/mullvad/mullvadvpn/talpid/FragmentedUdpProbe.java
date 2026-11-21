package net.mullvad.mullvadvpn.talpid;

import android.os.Bundle;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.security.SecureRandom;
import net.mullvad.mullvadvpn.test.publicdns.PublicDnsExchange;
import net.mullvad.mullvadvpn.test.publicdns.PublicDnsWire;
import org.json.JSONObject;

/** Historical randomized 4096-byte ordinary-UID query, sharing the stock-neutral probe. */
final class FragmentedUdpProbe {
  interface SocketOwner {
    void register(FileDescriptor socket) throws IOException;
  }

  private FragmentedUdpProbe() {}

  static Bundle run(File privateFiles, int family, SocketOwner owner) {
    Bundle result = new Bundle();
    try {
      SecureRandom random = new SecureRandom();
      byte[] nonce = new byte[32];
      random.nextBytes(nonce);
      JSONObject report = PublicDnsExchange.run(privateFiles, family,
          family == 4 ? "1.1.1.1" : "2606:4700:4700::1111",
          query(random.nextInt(65536), nonce), owner::register);
      if (report.getString("classification").equals("probe-error")) {
        throw new IllegalStateException("Public DNS diagnostic failed: " + report);
      }
      result.putString("outcome", report.getBoolean("validated") ? "fragmented-udp" : "failed");
      result.putString("fragment_report", report.toString());
    } catch (Exception error) {
      // A custody failure must remain a harness failure, not an informational DNS timeout.
      throw new IllegalStateException("Cannot retain public DNS evidence", error);
    }
    return result;
  }

  static byte[] query(int id, byte[] nonce) {
    return PublicDnsWire.query(id, nonce, 4096);
  }

  static void validateReply(byte[] bytes, int length, int id) throws IOException {
    PublicDnsWire.validateReply(bytes, length, id);
  }
}
