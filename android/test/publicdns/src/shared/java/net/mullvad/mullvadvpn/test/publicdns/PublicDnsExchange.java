package net.mullvad.mullvadvpn.test.publicdns;

import android.net.InetAddresses;
import android.os.Build;
import android.os.Process;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.JSONException;
import org.json.JSONObject;

/** One send and one receive under an ordinary UID; no protect, bind, retry or TCP fallback. */
public final class PublicDnsExchange {
  private static final int IP_MTU_DISCOVER = 10;
  private static final int IPV6_MTU_DISCOVER = 23;

  public interface SocketOwner {
    void register(FileDescriptor socket) throws IOException;
  }

  private PublicDnsExchange() {}

  public static JSONObject run(File privateFiles, int family, String peer, byte[] query,
      SocketOwner owner) throws IOException, JSONException {
    // These public socket APIs start at Q. Refuse unsupported diagnostic execution,
    // rather than resolving hostnames or silently dropping syscall timeout evidence.
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
      throw new UnsupportedOperationException("Public DNS syscall diagnostic requires Android 10");
    }
    if ((family != 4 && family != 6) || !InetAddresses.isNumericAddress(peer)) {
      throw new IllegalArgumentException("Explicit numeric IPv4/IPv6 peer required");
    }
    InetAddress destination = InetAddresses.parseNumericAddress(peer);
    if (destination.getAddress().length != (family == 4 ? 4 : 16)
        || (query.length != 76 && query.length != 4096)) {
      throw new IllegalArgumentException("Peer family/request size mismatch");
    }
    PrivateDnsBytes files = new PrivateDnsBytes(privateFiles);
    JSONObject report = new JSONObject();
    report.put("schema", 1);
    report.put("family", family);
    report.put("uid", Process.myUid());
    report.put("pid", Process.myPid());
    report.put("dns_id", (query[0] & 255) << 8 | (query[1] & 255));
    report.put("query", metadata(files.save("query.bin", query)));
    report.put("remote_address", destination.getHostAddress());
    report.put("remote_port", 53);
    report.put("request_bytes", query.length);
    report.put("timeout_ms", 5000);
    report.put("receive_calls", 0);
    report.put("send_calls", 0);
    report.put("validated", false);
    report.put("semantic_usable_a", false);
    report.put("recvmsg_flags_observed", false);
    FileDescriptor socket = null;
    boolean callerOwnsSocket = false;
    String stage = "create";
    try {
      socket = Os.socket(family == 4 ? OsConstants.AF_INET : OsConstants.AF_INET6,
          OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP);
      if (owner != null) {
        owner.register(socket);
        callerOwnsSocket = true;
      }
      stage = "mtu-option";
      int level = family == 4 ? OsConstants.IPPROTO_IP : OsConstants.IPPROTO_IPV6;
      int option = family == 4 ? IP_MTU_DISCOVER : IPV6_MTU_DISCOVER;
      // Linux PMTUDISC_DONT=0, as in the original probe. Packet capture proves fragmentation.
      Os.setsockoptInt(socket, level, option, 0);
      report.put("option_level", level);
      report.put("option_name", option);
      report.put("option_value", 0);
      report.put("option_set", true);
      Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO,
          StructTimeval.fromMillis(5000));
      Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO,
          StructTimeval.fromMillis(5000));
      stage = "connect";
      Os.connect(socket, destination, 53);
      InetSocketAddress local = (InetSocketAddress) Os.getsockname(socket);
      report.put("local_address", local.getAddress().getHostAddress());
      report.put("local_port", local.getPort());
      stage = "send";
      report.put("send_started_ns", SystemClock.elapsedRealtimeNanos());
      report.put("send_calls", 1);
      int sent = Os.sendto(socket, query, 0, query.length, 0, destination, 53);
      report.put("sent", sent);
      report.put("send_completed_ns", SystemClock.elapsedRealtimeNanos());
      if (sent != query.length) throw new IOException("Short DNS datagram send");
      stage = "receive";
      byte[] buffer = new byte[65535];
      InetSocketAddress source = new InetSocketAddress(0);
      report.put("receive_calls", 1);
      report.put("receive_started_ns", SystemClock.elapsedRealtimeNanos());
      // Linux MSG_TRUNC returns the original datagram length, not just copied bytes.
      // Android Os exposes recvfrom, not ancillary recvmsg flags. Record that limit explicitly.
      int count = Os.recvfrom(socket, buffer, 0, buffer.length, OsConstants.MSG_TRUNC, source);
      report.put("received_ns", SystemClock.elapsedRealtimeNanos());
      report.put("received", count);
      report.put("reply_source", source.getAddress().getHostAddress());
      report.put("reply_port", source.getPort());
      byte[] reply = Arrays.copyOf(buffer, Math.min(count, buffer.length));
      // Always durable BEFORE source, envelope, truncation or semantic validation.
      report.put("response", metadata(files.save("response-000.bin", reply)));
      stage = "validate";
      PublicDnsWire.Audit audit = PublicDnsWire.auditDatagram(reply, report.getInt("dns_id"),
          destination.getAddress(), source.getAddress().getAddress(), source.getPort(), count > buffer.length);
      report.put("classification", audit.classification);
      report.put("validation_reason", audit.reason);
      report.put("validated", audit.envelopeValid);
      report.put("semantic_usable_a", audit.usableA);
      report.put("rcode", audit.responseCode);
      report.put("answer_count", audit.answerCount);
    } catch (Exception error) {
      report.put("error_stage", stage);
      report.put("error_class", error.getClass().getName());
      String reason = String.valueOf(error.getMessage());
      report.put("error_reason", reason.substring(0, Math.min(reason.length(), 512)));
      String classification = "probe-error";
      if (error instanceof ErrnoException) {
        int errno = ((ErrnoException) error).errno;
        report.put("errno", errno);
        classification = "socket-error";
        if (errno == OsConstants.EAGAIN && (stage.equals("send") || stage.equals("receive"))) {
          classification = stage + "-timeout";
        }
      }
      report.put("classification", classification);
    } finally {
      if (callerOwnsSocket) report.put("socket_close_owner", "caller");
      if (!callerOwnsSocket && socket != null && socket.valid()) {
        try {
          Os.close(socket);
          report.put("socket_closed", true);
        } catch (ErrnoException error) {
          report.put("socket_close_errno", error.errno);
        }
      }
      report.put("completed_ns", SystemClock.elapsedRealtimeNanos());
    }
    PrivateDnsBytes.Saved receipt = files.save("receipt.json",
        report.toString().getBytes(StandardCharsets.UTF_8));
    report.put("receipt", metadata(receipt));
    return report;
  }

  private static JSONObject metadata(PrivateDnsBytes.Saved saved) throws JSONException {
    return new JSONObject().put("path", saved.path).put("size", saved.size).put("sha256", saved.sha256);
  }
}
