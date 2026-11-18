package net.mullvad.mullvadvpn.talpid;

import java.io.IOException;
import java.util.Arrays;

/** Builder-only executable assertions for the exact Java consumer byte contract. */
final class LocalUdpPayloadTest {
  private static void rejects(byte[] expected, byte[] reply, int count) throws Exception {
    try {
      LocalUdpPayload.validate(expected, reply, count);
      throw new AssertionError("Accepted incomplete, corrupt or truncated UDP reply");
    } catch (IOException expectedFailure) {
      // The rejection, not an exception from a socket/harness, is the observation.
    }
  }

  public static void main(String[] args) throws Exception {
    byte[] nonce = new byte[32];
    for (int index = 0; index < nonce.length; index++) nonce[index] = (byte) index;
    int checks = 0;
    if (!ProbePayloadSummary.sha256(new byte[0], 0).equals(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
      throw new AssertionError("SHA256 known answer");
    for (int size : new int[] {0, 1, 31, 32, 1232, 1233, 1252, 1253, 4096, 4097, 65487, 65488, 65507, 65508}) {
      byte[] request = LocalUdpPayload.create(size, nonce);
      if (request.length != size) throw new AssertionError("Payload length");
      for (int index = 0; index < size; index++) {
        int expected = index < 32 ? nonce[index] : (nonce[index % 32] ^ (index * 31 + index / 32));
        if (request[index] != (byte) expected) throw new AssertionError("Payload pattern");
      }
      byte[] buffer = new byte[65535];
      System.arraycopy(request, 0, buffer, 0, size);
      LocalUdpPayload.validate(request, buffer, size);
      String digest = ProbePayloadSummary.sha256(request, size);
      if (digest.length() != 64 || !digest.equals(ProbePayloadSummary.sha256(buffer, size)))
        throw new AssertionError("Bounded full-byte digest");
      rejects(request, buffer, size + 1);
      rejects(request, buffer, -1);
      if (size > 0) {
        rejects(request, buffer, size - 1);
        rejects(request, Arrays.copyOf(buffer, size - 1), size);
        buffer[size - 1] ^= 1;
        rejects(request, buffer, size);
        if (digest.equals(ProbePayloadSummary.sha256(buffer, size)))
          throw new AssertionError("Digest missed altered tail");
      }
      checks++;
    }
    for (int size : new int[] {-1, 65509, Integer.MAX_VALUE}) {
      try {
        LocalUdpPayload.create(size, nonce);
        throw new AssertionError("Invalid size accepted");
      } catch (IllegalArgumentException expected) {
        checks++;
      }
    }
    System.out.println("LocalUdpPayload: " + checks + " size cases passed; exact bytes and negative comparisons");
  }
}
