package net.mullvad.mullvadvpn.test.publicdns;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** Diagnostic wire audit only. This is not a resolver or the product split-DNS parser. */
public final class PublicDnsWire {
  private static final byte[] QUESTION = {
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1
  };

  private PublicDnsWire() {}

  /** The historical vector and its matched control differ only in padding length. */
  public static byte[] query(int id, byte[] nonce, int size) {
    if (id < 0 || id > 65535 || nonce.length != 32 || (size != 76 && size != 4096)) {
      throw new IllegalArgumentException("DNS ID, 32-byte nonce, and 76/4096-byte request required");
    }
    byte[] bytes = new byte[size];
    putWord(bytes, 0, id);
    putWord(bytes, 2, 0x0100);
    putWord(bytes, 4, 1);
    putWord(bytes, 10, 1);
    System.arraycopy(QUESTION, 0, bytes, 12, QUESTION.length);
    putWord(bytes, 30, 41);
    putWord(bytes, 32, 4096);
    putWord(bytes, 38, size - 40);
    putWord(bytes, 40, 12);
    putWord(bytes, 42, size - 44);
    System.arraycopy(nonce, 0, bytes, 44, nonce.length);
    return bytes;
  }

  public static final class Audit {
    public final String classification;
    public final String reason;
    public final boolean envelopeValid;
    public final boolean usableA;
    public final int responseCode;
    public final int answerCount;

    private Audit(String classification, String reason, boolean envelopeValid, boolean usableA,
        int responseCode, int answerCount) {
      this.classification = classification;
      this.reason = reason;
      this.envelopeValid = envelopeValid;
      this.usableA = usableA;
      this.responseCode = responseCode;
      this.answerCount = answerCount;
    }
  }

  /** Retains the historical successful-envelope guarantees separately from A-answer semantics. */
  public static Audit audit(byte[] bytes, int id) {
    try {
      return decode(bytes, id);
    } catch (IOException malformed) {
      return new Audit("malformed", malformed.getMessage(), false, false, -1, -1);
    }
  }

  public static Audit auditDatagram(byte[] bytes, int id, byte[] expectedSource,
      byte[] actualSource, int sourcePort, boolean truncated) {
    if (truncated) return new Audit("truncated-datagram", "Receive buffer truncated datagram", false, false, -1, -1);
    if (!Arrays.equals(expectedSource, actualSource) || sourcePort != 53) {
      return new Audit("wrong-source", "Unexpected DNS response source/port", false, false, -1, -1);
    }
    return audit(bytes, id);
  }

  public static void validateReply(byte[] bytes, int length, int id) throws IOException {
    if (length < 0 || length > bytes.length) throw new IOException("Invalid DNS byte count");
    Audit result = audit(Arrays.copyOf(bytes, length), id);
    if (!result.envelopeValid) throw new IOException(result.classification + ": " + result.reason);
  }

  private static Audit decode(byte[] bytes, int id) throws IOException {
    if (bytes.length < 12) throw new IOException("Truncated DNS header");
    int flags = word(bytes, 2);
    int answers = word(bytes, 6);
    if (word(bytes, 0) != id || (flags & 0xf800) != 0x8000 || word(bytes, 4) != 1) {
      return new Audit("wrong-identity", "DNS ID/QR/opcode/question count mismatch", false, false,
          flags & 15, answers);
    }
    Name question = name(bytes, 12);
    int cursor = question.end;
    require(bytes, cursor, 4);
    if (!question.value.equals("example.com.")
        || word(bytes, cursor) != 1 || word(bytes, cursor + 2) != 1) {
      return new Audit("wrong-identity", "DNS question name/type/class mismatch", false, false,
          flags & 15, answers);
    }
    cursor += 4;
    int authorities = word(bytes, 8);
    int total = answers + authorities + word(bytes, 10);
    int extendedCode = 0;
    boolean optSeen = false;
    boolean invalidAnswer = false;
    List<Record> records = new ArrayList<>();
    for (int index = 0; index < total; index++) {
      Name owner = name(bytes, cursor);
      cursor = owner.end;
      require(bytes, cursor, 10);
      int type = word(bytes, cursor);
      int dnsClass = word(bytes, cursor + 2);
      int length = word(bytes, cursor + 8);
      int ttlStart = cursor + 4;
      cursor += 10;
      require(bytes, cursor, length);
      String alias = null;
      if (index < answers && type == 5) {
        Name target = name(bytes, cursor);
        if (target.end != cursor + length) throw new IOException("Invalid CNAME RDATA length");
        alias = target.value;
      }
      if (type == 41) {
        if (optSeen || !owner.value.equals(".") || index < answers + authorities) {
          throw new IOException("Invalid OPT owner/section/count");
        }
        optSeen = true;
        extendedCode = (bytes[ttlStart] & 255) << 4;
        int option = cursor;
        while (option < cursor + length) {
          if (cursor + length - option < 4) throw new IOException("Truncated EDNS option");
          int optionLength = word(bytes, option + 2);
          option += 4;
          if (optionLength > cursor + length - option) throw new IOException("Truncated EDNS data");
          option += optionLength;
        }
      }
      if (index < answers) {
        if (type == 1 && length != 4) invalidAnswer = true;
        records.add(new Record(owner.value, type, dnsClass, length, alias));
      }
      cursor += length;
    }
    if (cursor != bytes.length) throw new IOException("Trailing DNS bytes");
    int code = extendedCode | (flags & 15);
    if ((flags & 0x0200) != 0) return new Audit("tc", "DNS TC flag", false, false, code, answers);
    // Legacy validation checked only the header rcode, not the OPT extended rcode.
    boolean envelope = (flags & 15) == 0 && answers > 0;
    if (code != 0) return new Audit("rcode", "DNS response code " + code, envelope, false, code, answers);
    if (answers == 0) return new Audit("no-answer", "NOERROR without answers", false, false, code, 0);
    if (invalidAnswer) {
      return new Audit("unusable-answer", "Invalid A RDATA length", envelope, false, code, answers);
    }
    String current = "example.com.";
    List<String> visited = new ArrayList<>();
    for (int hop = 0; hop <= records.size(); hop++) {
      if (visited.contains(current)) break;
      visited.add(current);
      String next = null;
      boolean address = false;
      boolean ambiguous = false;
      for (Record record : records) {
        if (!record.owner.equals(current) || record.dnsClass != 1) continue;
        if (record.type == 1 && record.length == 4) address = true;
        if (record.type == 5) {
          if (next != null && !next.equals(record.alias)) ambiguous = true;
          next = record.alias;
        }
      }
      if (ambiguous || (address && next != null)) break;
      if (address) return new Audit("usable-a", "Complete matching A/IN answer", envelope, true, code, answers);
      if (next == null) break;
      current = next;
    }
    return new Audit("unusable-answer", "No unambiguous A/IN answer for question or CNAME chain",
        envelope, false, code, answers);
  }

  private static final class Record {
    final String owner;
    final int type;
    final int dnsClass;
    final int length;
    final String alias;

    Record(String owner, int type, int dnsClass, int length, String alias) {
      this.owner = owner;
      this.type = type;
      this.dnsClass = dnsClass;
      this.length = length;
      this.alias = alias;
    }
  }

  private static final class Name {
    final int end;
    final String value;

    Name(int end, String value) {
      this.end = end;
      this.value = value;
    }
  }

  private static Name name(byte[] bytes, int start) throws IOException {
    int cursor = start;
    int end = -1;
    int expanded = 0;
    StringBuilder value = new StringBuilder();
    for (int hops = 0; hops < bytes.length; hops++) {
      require(bytes, cursor, 1);
      int size = bytes[cursor] & 255;
      if ((size & 0xc0) == 0xc0) {
        require(bytes, cursor, 2);
        if (end < 0) end = cursor + 2;
        int target = ((size & 63) << 8) | (bytes[cursor + 1] & 255);
        if (target >= cursor) throw new IOException("DNS pointer is not to a prior occurrence");
        cursor = target;
        continue;
      }
      expanded += 1 + size;
      if (size > 63 || expanded > 255) throw new IOException("Invalid DNS name boundary");
      require(bytes, cursor + 1, size);
      cursor += 1;
      if (size == 0) return new Name(end < 0 ? cursor : end, value.length() == 0 ? "." : value.toString());
      for (int index = 0; index < size; index++) {
        int labelByte = bytes[cursor + index] & 255;
        // Escape arbitrary label bytes so equality cannot confuse a literal dot with a boundary.
        if (labelByte <= 32 || labelByte >= 127 || labelByte == '.' || labelByte == '\\') {
          value.append('\\').append(String.format(Locale.ROOT, "%03d", labelByte));
        } else {
          value.append((char) (labelByte >= 'A' && labelByte <= 'Z' ? labelByte + 32 : labelByte));
        }
      }
      value.append('.');
      cursor += size;
    }
    throw new IOException("DNS compression loop");
  }

  private static void require(byte[] bytes, int offset, int count) throws IOException {
    if (offset < 0 || count < 0 || offset > bytes.length || count > bytes.length - offset) {
      throw new IOException("Truncated DNS field");
    }
  }

  private static int word(byte[] bytes, int offset) {
    return (bytes[offset] & 255) << 8 | (bytes[offset + 1] & 255);
  }

  private static void putWord(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) (value >>> 8);
    bytes[offset + 1] = (byte) value;
  }
}
