package net.mullvad.mullvadvpn.talpid;

import java.io.IOException;
import java.util.Arrays;

/** Java-only payload contract, also exercised without an Android runtime in the builder. */
final class LocalUdpPayload {
  private LocalUdpPayload() {}

  static byte[] create(int size, byte[] nonce) {
    if (size < 0 || size > 65508 || nonce.length != 32)
      throw new IllegalArgumentException("UDP payload size/nonce");
    byte[] bytes = new byte[size];
    for (int i = 0; i < size; i++)
      bytes[i] = i < 32 ? nonce[i] : (byte) (nonce[i % 32] ^ (i * 31 + i / 32));
    return bytes;
  }

  static void validate(byte[] request, byte[] reply, int count) throws IOException {
    if (count != request.length || count > reply.length || count < 0
        || !Arrays.equals(request, Arrays.copyOf(reply, count)))
      throw new IOException("UDP full payload mismatch or truncation");
  }
}
