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

/** Ordinary test-APK UID sockets only. Root capture is a separate external observer. */
final class FragmentedUdpProbe {
  // Linux UAPI linux/in.h and linux/in6.h. Not all SDKs expose these constants.
  private static final int IP_MTU_DISCOVER = 10;
  private static final int IPV6_MTU_DISCOVER = 23;
  private static final int PMTUDISC_DONT = 0;
  private static final byte[] QUESTION = {
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1
  };

  interface SocketOwner {
    void register(FileDescriptor socket) throws IOException;
  }

  private FragmentedUdpProbe() {}

  static Bundle run(int family, SocketOwner owner) {
    Bundle result = new Bundle();
    JSONObject report = new JSONObject();
    String stage = "create";
    try {
      report.put("family", family);
      report.put("uid", Process.myUid());
      report.put("pid", Process.myPid());
      int domain = family == 4 ? OsConstants.AF_INET : OsConstants.AF_INET6;
      int level = family == 4 ? OsConstants.IPPROTO_IP : OsConstants.IPPROTO_IPV6;
      int option = family == 4 ? IP_MTU_DISCOVER : IPV6_MTU_DISCOVER;
      InetAddress destination = InetAddress.getByName(
          family == 4 ? "1.1.1.1" : "2606:4700:4700::1111");
      FileDescriptor socket = Os.socket(domain, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP);
      owner.register(socket);
      stage = "mtu-option";
      report.put("option_level", level);
      report.put("option_name", option);
      report.put("option_value", PMTUDISC_DONT);
      // A failed set throws ErrnoException. Actual fragmentation is proven by
      // the independent external TUN capture, not inferred from this return.
      Os.setsockoptInt(socket, level, option, PMTUDISC_DONT);
      report.put("option_set", true);
      Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO,
          StructTimeval.fromMillis(5000));
      Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO,
          StructTimeval.fromMillis(5000));
      stage = "connect";
      // UDP connect selects the normal app-facing route and a local tuple. This
      // is not VpnService.protect, Network.bindSocket or a physical-network bind.
      Os.connect(socket, destination, 53);
      InetSocketAddress local = (InetSocketAddress) Os.getsockname(socket);
      report.put("local_address", local.getAddress().getHostAddress());
      report.put("local_port", local.getPort());
      report.put("remote_address", destination.getHostAddress());
      report.put("remote_port", 53);
      SecureRandom random = new SecureRandom();
      int id = random.nextInt(65536);
      byte[] nonce = new byte[32];
      random.nextBytes(nonce);
      byte[] query = query(id, nonce);
      report.put("dns_id", id);
      report.put("padding_nonce", hex(nonce));
      report.put("query_hex", hex(query));
      report.put("send_started_ns", SystemClock.elapsedRealtimeNanos());
      stage = "send";
      int sent = Os.sendto(socket, query, 0, query.length, 0, destination, 53);
      report.put("sent", sent);
      report.put("send_completed_ns", SystemClock.elapsedRealtimeNanos());
      if (sent != query.length) throw new IOException("Short DNS datagram send");
      stage = "receive";
      byte[] reply = new byte[65535];
      InetSocketAddress source = new InetSocketAddress(0);
      int count = Os.recvfrom(socket, reply, 0, reply.length, 0, source);
      report.put("received_ns", SystemClock.elapsedRealtimeNanos());
      report.put("reply_source", source.getAddress().getHostAddress());
      report.put("reply_port", source.getPort());
      report.put("received", count);
      report.put("reply_hex", hex(Arrays.copyOf(reply, count)));
      stage = "validate";
      if (!source.getAddress().equals(destination) || source.getPort() != 53) {
        throw new IOException("Unexpected DNS response source");
      }
      validateReply(reply, count, id);
      result.putString("outcome", "fragmented-udp");
      report.put("validated", true);
    } catch (Exception error) {
      result.putString("outcome", "failed");
      reportError(report, stage, error);
    }
    result.putString("fragment_report", report.toString());
    return result;
  }

  private static void reportError(JSONObject report, String stage, Exception error) {
    try {
      report.put("error_stage", stage);
      report.put("error_class", error.getClass().getName());
      report.put("error_reason", String.valueOf(error.getMessage()));
      if (error instanceof ErrnoException) report.put("errno", ((ErrnoException) error).errno);
    } catch (org.json.JSONException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  static byte[] query(int id, byte[] nonce) {
    if (nonce.length != 32) throw new IllegalArgumentException("32-byte padding nonce");
    byte[] query = new byte[4096];
    query[0] = (byte) (id >>> 8);
    query[1] = (byte) id;
    query[2] = 1; // RD, standard query.
    query[5] = 1; // One question.
    query[11] = 1; // One OPT record.
    System.arraycopy(QUESTION, 0, query, 12, QUESTION.length);
    int offset = 12 + QUESTION.length;
    query[offset + 2] = 41; // OPT, advertised UDP payload size 4096.
    query[offset + 3] = 0x10;
    int dataLength = query.length - offset - 11;
    query[offset + 9] = (byte) (dataLength >>> 8);
    query[offset + 10] = (byte) dataLength;
    query[offset + 12] = 12; // RFC 7830 Padding option.
    int padding = dataLength - 4;
    query[offset + 13] = (byte) (padding >>> 8);
    query[offset + 14] = (byte) padding;
    System.arraycopy(nonce, 0, query, offset + 15, nonce.length);
    return query;
  }

  static void validateReply(byte[] bytes, int length, int id) throws IOException {
    if (length < 12 + QUESTION.length || length > bytes.length
        || word(bytes, 0) != id || (word(bytes, 2) & 0xfa0f) != 0x8000
        || word(bytes, 4) != 1 || word(bytes, 6) == 0) {
      throw new IOException("DNS ID/QR/opcode/TC/rcode/count mismatch");
    }
    int cursor = nameEnd(bytes, length, 12, true);
    if (cursor + 4 > length || word(bytes, cursor) != 1 || word(bytes, cursor + 2) != 1) {
      throw new IOException("DNS question type/class mismatch");
    }
    cursor += 4;
    int records = word(bytes, 6) + word(bytes, 8) + word(bytes, 10);
    for (int record = 0; record < records; record++) {
      cursor = nameEnd(bytes, length, cursor, false);
      if (cursor + 10 > length) throw new IOException("Truncated DNS record header");
      int dataLength = word(bytes, cursor + 8);
      cursor += 10;
      if (dataLength > length - cursor) throw new IOException("Truncated DNS RDATA");
      cursor += dataLength;
    }
    if (cursor != length) throw new IOException("Trailing DNS bytes");
  }

  // Return the original wire end, independently of pointer traversal. Every
  // declared record uses the same bounded name parser as the echoed question.
  private static int nameEnd(byte[] bytes, int length, int start, boolean question)
      throws IOException {
    int cursor = start;
    int end = -1;
    int expected = 0;
    int expanded = 0;
    for (int hops = 0; hops < length; hops++) {
      if (cursor >= length) throw new IOException("Truncated DNS name");
      int size = bytes[cursor] & 255;
      if ((size & 0xc0) == 0xc0) {
        if (cursor + 1 >= length) throw new IOException("Truncated DNS pointer");
        if (end < 0) end = cursor + 2;
        cursor = ((size & 63) << 8) | (bytes[cursor + 1] & 255);
        continue;
      }
      expanded += 1 + size;
      if (size > 63 || expanded > 255 || cursor + 1 + size > length) {
        throw new IOException("Invalid DNS name boundary");
      }
      if (question) {
        if (expected + 1 + size > 13 || size != QUESTION[expected]) {
          throw new IOException("DNS question name mismatch");
        }
        for (int i = 1; i <= size; i++) {
          if (Character.toLowerCase((char) (bytes[cursor + i] & 255)) != QUESTION[expected + i]) {
            throw new IOException("DNS question label mismatch");
          }
        }
        expected += 1 + size;
      }
      cursor += 1 + size;
      if (size != 0) continue;
      if (question && expected != 13) throw new IOException("DNS question name mismatch");
      return end < 0 ? cursor : end;
    }
    throw new IOException("DNS compression loop");
  }

  private static int word(byte[] bytes, int offset) {
    return (bytes[offset] & 255) << 8 | (bytes[offset + 1] & 255);
  }

  private static String hex(byte[] bytes) {
    StringBuilder result = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) {
      result.append("0123456789abcdef".charAt((value & 255) >>> 4));
      result.append("0123456789abcdef".charAt(value & 15));
    }
    return result.toString();
  }
}
