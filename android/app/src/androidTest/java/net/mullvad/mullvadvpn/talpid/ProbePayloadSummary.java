package net.mullvad.mullvadvpn.talpid;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Fixed-size byte identity for Binder reports; validation still consumes the original bytes. */
final class ProbePayloadSummary {
  private ProbePayloadSummary() {}

  static String sha256(byte[] bytes, int count) {
    if (count < 0 || count > bytes.length) throw new IllegalArgumentException("Digest length");
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(bytes, 0, count);
      StringBuilder text = new StringBuilder(64);
      for (byte value : digest.digest()) {
        text.append("0123456789abcdef".charAt((value & 255) >>> 4));
        text.append("0123456789abcdef".charAt(value & 15));
      }
      return text.toString();
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }
}
