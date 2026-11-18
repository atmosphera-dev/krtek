package net.mullvad.mullvadvpn.talpid;

import android.net.InetAddresses;
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
import org.json.JSONObject;

/** Full UDP datagrams from the neutral consumer UID. Never protects or binds a network. */
final class LocalUdpProbe {
  private LocalUdpProbe() {}

  static Bundle run(String destination, int size, FragmentedUdpProbe.SocketOwner owner) {
    return run(destination, size, 0, owner);
  }

  static Bundle replyLimit(String destination, int replySize, FragmentedUdpProbe.SocketOwner owner) {
    return run(destination, 32, replySize, owner);
  }

  private static Bundle run(String destination, int size, int replySize,
      FragmentedUdpProbe.SocketOwner owner) {
    Bundle result = new Bundle();
    JSONObject report = new JSONObject();
    String stage = "create";
    try {
      InetAddress remote = InetAddresses.parseNumericAddress(destination);
      int family = remote.getAddress().length == 4 ? 4 : 6;
      report.put("family", family);
      report.put("uid", Process.myUid());
      report.put("pid", Process.myPid());
      report.put("payload_size", size);
      if (replySize != 0) report.put("requested_reply_size", replySize);
      report.put("remote_address", remote.getHostAddress());
      report.put("remote_port", 18081);
      report.put("socket_kind", "udp-dgram");
      byte[] nonce = new byte[32];
      new SecureRandom().nextBytes(nonce);
      byte[] request = LocalUdpPayload.create(size, nonce);
      report.put("nonce", hex(nonce));
      // Binder carries only fixed-size identities, never either datagram.
      report.put("payload_sha256", ProbePayloadSummary.sha256(request, request.length));
      FileDescriptor socket = Os.socket(family == 4 ? OsConstants.AF_INET : OsConstants.AF_INET6,
          OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP);
      owner.register(socket);
      // Permit the Android kernel to fragment the ordinary UDP send. This is not
      // a raw sender or a VPN bypass: route/network selection stays with Android.
      stage = "mtu-option";
      int level = family == 4 ? OsConstants.IPPROTO_IP : OsConstants.IPPROTO_IPV6;
      int option = family == 4 ? 10 : 23; // Linux IP[V6]_MTU_DISCOVER.
      Os.setsockoptInt(socket, level, option, 0);
      report.put("option_set", true);
      report.put("option_level", level);
      report.put("option_name", option);
      report.put("option_value", 0);
      Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO,
          StructTimeval.fromMillis(5000));
      Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO,
          StructTimeval.fromMillis(5000));
      stage = "connect";
      Os.connect(socket, remote, 18081);
      InetSocketAddress local = (InetSocketAddress) Os.getsockname(socket);
      report.put("local_address", local.getAddress().getHostAddress());
      report.put("local_port", local.getPort());
      stage = "send";
      report.put("send_started_ns", SystemClock.elapsedRealtimeNanos());
      int sent = Os.sendto(socket, request, 0, request.length, 0, remote, 18081);
      report.put("sent", sent);
      report.put("send_completed_ns", SystemClock.elapsedRealtimeNanos());
      if (sent != request.length) throw new IOException("Short UDP send");
      stage = "receive";
      // One receive, not a stream/prefix/ACK. MSG_TRUNC exposes the original
      // datagram length even if a future edit accidentally shrinks this buffer.
      byte[] reply = new byte[65535];
      InetSocketAddress source = new InetSocketAddress(0);
      int count = Os.recvfrom(socket, reply, 0, reply.length, OsConstants.MSG_TRUNC, source);
      report.put("received_ns", SystemClock.elapsedRealtimeNanos());
      report.put("received", count);
      report.put("reply_source", source.getAddress().getHostAddress());
      report.put("reply_port", source.getPort());
      report.put("reply_sha256", ProbePayloadSummary.sha256(reply, Math.min(count, reply.length)));
      stage = "validate";
      boolean sourceMatches = remote.equals(source.getAddress()) && source.getPort() == 18081;
      report.put("source_matches", sourceMatches);
      if (!sourceMatches)
        throw new IOException("Unexpected UDP source tuple");
      report.put("bytes_equal", false);
      LocalUdpPayload.validate(request, reply, count);
      report.put("bytes_equal", true);
      report.put("validated", true);
      result.putString("outcome", "local-udp-echo");
    } catch (Exception error) {
      result.putString("outcome", "failed");
      try {
        report.put("error_stage", stage);
        report.put("error_class", error.getClass().getName());
        String reason = String.valueOf(error.getMessage());
        report.put("error_reason", reason.substring(0, Math.min(reason.length(), 512)));
        if (error instanceof ErrnoException) report.put("errno", ((ErrnoException) error).errno);
      } catch (org.json.JSONException impossible) {
        throw new IllegalStateException(impossible);
      }
    }
    result.putString("local_udp_report", report.toString());
    return result;
  }

  private static String hex(byte[] bytes) {
    StringBuilder text = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) {
      text.append("0123456789abcdef".charAt((value & 255) >>> 4));
      text.append("0123456789abcdef".charAt(value & 15));
    }
    return text.toString();
  }
}
