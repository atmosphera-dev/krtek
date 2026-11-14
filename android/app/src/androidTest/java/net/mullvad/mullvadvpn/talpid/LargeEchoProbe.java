package net.mullvad.mullvadvpn.talpid;

import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;
import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import org.json.JSONObject;

/** Test-only ordinary-UID ping sockets. No protect, network bind or privileged sender. */
final class LargeEchoProbe {
  private LargeEchoProbe() {}

  static Bundle run(int family, int size, FragmentedUdpProbe.SocketOwner owner) {
    Bundle result = new Bundle();
    JSONObject report = new JSONObject();
    String stage = "create";
    try {
      report.put("family", family);
      report.put("uid", Process.myUid());
      report.put("pid", Process.myPid());
      report.put("payload_size", size);
      int protocol = family == 4 ? OsConstants.IPPROTO_ICMP : OsConstants.IPPROTO_ICMPV6;
      int level = family == 4 ? OsConstants.IPPROTO_IP : OsConstants.IPPROTO_IPV6;
      int option = family == 4 ? 10 : 23; // Linux IP[V6]_MTU_DISCOVER.
      InetAddress remote = InetAddress.getByName(
          family == 4 ? "10.64.0.1" : "fc00:bbbb:bbbb:bb01::1");
      FileDescriptor socket = Os.socket(family == 4 ? OsConstants.AF_INET : OsConstants.AF_INET6,
          OsConstants.SOCK_DGRAM, protocol);
      owner.register(socket);
      report.put("socket_kind", "icmp-dgram");
      report.put("option_level", level);
      report.put("option_name", option);
      report.put("option_value", 0);
      stage = "mtu-option";
      Os.setsockoptInt(socket, level, option, 0);
      report.put("option_set", true);
      Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO,
          StructTimeval.fromMillis(5000));
      Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO,
          StructTimeval.fromMillis(5000));
      stage = "connect";
      Os.connect(socket, remote, 0);
      InetSocketAddress local = (InetSocketAddress) Os.getsockname(socket);
      report.put("local_address", local.getAddress().getHostAddress());
      report.put("remote_address", remote.getHostAddress());
      byte[] nonce = new byte[32];
      new SecureRandom().nextBytes(nonce);
      byte[] payload = payload(size, nonce);
      byte[] request = new byte[8 + payload.length];
      request[0] = (byte) (family == 4 ? 8 : 128);
      request[7] = 1;
      System.arraycopy(payload, 0, request, 8, payload.length);
      if (family == 4) {
        int sum = checksum(request);
        request[2] = (byte) (sum >>> 8);
        request[3] = (byte) sum;
      } // ICMPv6 ping sockets compute the pseudoheader checksum in the kernel.
      report.put("nonce", hex(nonce));
      report.put("payload_hex", hex(payload));
      report.put("sequence", 1);
      report.put("send_started_ns", SystemClock.elapsedRealtimeNanos());
      stage = "send";
      int sent = Os.sendto(socket, request, 0, request.length, 0, remote, 0);
      report.put("sent", sent);
      report.put("send_completed_ns", SystemClock.elapsedRealtimeNanos());
      if (sent != request.length) throw new IOException("Short echo send");
      int identifier = ((InetSocketAddress) Os.getsockname(socket)).getPort();
      report.put("identifier", identifier);
      stage = "receive";
      byte[] reply = new byte[8192];
      InetSocketAddress source = new InetSocketAddress(0);
      int count = Os.recvfrom(socket, reply, 0, reply.length, 0, source);
      report.put("received_ns", SystemClock.elapsedRealtimeNanos());
      report.put("reply_source", source.getAddress().getHostAddress());
      report.put("received", count);
      report.put("reply_hex", hex(Arrays.copyOf(reply, count)));
      stage = "validate";
      if (!source.getAddress().equals(remote)) throw new IOException("Unexpected echo source");
      validateReply(family, reply, count, identifier, payload,
          remote.getAddress(), local.getAddress().getAddress());
      report.put("validated", true);
      result.putString("outcome", "gateway-echo");
    } catch (Exception error) {
      result.putString("outcome", "failed");
      try {
        report.put("error_stage", stage);
        report.put("error_class", error.getClass().getName());
        report.put("error_reason", String.valueOf(error.getMessage()));
        if (error instanceof ErrnoException) report.put("errno", ((ErrnoException) error).errno);
      } catch (org.json.JSONException impossible) {
        throw new IllegalStateException(impossible);
      }
    }
    result.putString("echo_report", report.toString());
    return result;
  }

  static byte[] payload(int size, byte[] nonce) {
    if (!(size == 32 || size == 3072) || nonce.length != 32) {
      throw new IllegalArgumentException("Echo payload size/nonce");
    }
    byte[] bytes = new byte[size];
    for (int i = 0; i < size; i++) bytes[i] = (byte) (nonce[i % 32] ^ (i * 31 + i / 32));
    return bytes;
  }

  static void validateReply(int family, byte[] packet, int length, int identifier,
      byte[] payload, byte[] source, byte[] destination) throws IOException {
    if (length != payload.length + 8 || length > packet.length
        || (packet[0] & 255) != (family == 4 ? 0 : 129) || packet[1] != 0
        || ((packet[4] & 255) << 8 | (packet[5] & 255)) != identifier
        || packet[6] != 0 || packet[7] != 1
        || !Arrays.equals(payload, Arrays.copyOfRange(packet, 8, length))) {
      throw new IOException("Echo type/code/ID/sequence/full payload mismatch");
    }
    byte[] checked = Arrays.copyOf(packet, length);
    if (family == 6) {
      byte[] pseudo = new byte[40 + length];
      System.arraycopy(source, 0, pseudo, 0, 16);
      System.arraycopy(destination, 0, pseudo, 16, 16);
      pseudo[34] = (byte) (length >>> 8);
      pseudo[35] = (byte) length;
      pseudo[39] = 58;
      System.arraycopy(checked, 0, pseudo, 40, length);
      checked = pseudo;
    }
    if (checksum(checked) != 0) throw new IOException("Echo checksum mismatch");
  }

  static int checksum(byte[] bytes) {
    int sum = 0;
    for (int i = 0; i < bytes.length; i += 2) {
      sum += (bytes[i] & 255) << 8;
      if (i + 1 < bytes.length) sum += bytes[i + 1] & 255;
    }
    while ((sum >>> 16) != 0) sum = (sum & 65535) + (sum >>> 16);
    return (~sum) & 65535;
  }

  private static String hex(byte[] bytes) {
    StringBuilder result = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      result.append("0123456789abcdef".charAt((b & 255) >>> 4));
      result.append("0123456789abcdef".charAt(b & 15));
    }
    return result.toString();
  }
}
