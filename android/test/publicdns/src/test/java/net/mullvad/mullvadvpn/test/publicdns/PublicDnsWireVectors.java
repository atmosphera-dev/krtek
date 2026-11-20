package net.mullvad.mullvadvpn.test.publicdns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Independent literal DNS fixtures. Runnable without Android so the actual Java parser is exercised. */
public final class PublicDnsWireVectors {
  private static final int ID = 0x1234;
  private static final byte[] QUESTION = hex("076578616d706c6503636f6d0000010001");
  private static final byte[] GOOD = hex(
      "123481800001000100000000076578616d706c6503636f6d0000010001"
      + "c00c000100010000012c0004c0000201");

  private PublicDnsWireVectors() {}

  public static Map<String, Runnable> cases() {
    Map<String, Runnable> cases = new LinkedHashMap<>();
    cases.put("should preserve original 4096 byte golden", () -> golden(4096));
    cases.put("should construct matched 76 byte golden", () -> golden(76));
    cases.put("should reject invalid request contracts", () -> {
      rejectQuery(-1, 32, 76);
      rejectQuery(65536, 32, 76);
      rejectQuery(ID, 31, 76);
      rejectQuery(ID, 32, 512);
    });
    cases.put("should accept compressed owner A", () -> expect(GOOD, "usable-a", true, true));
    cases.put("should reject wrong response source and port", () -> {
      byte[] peer = {1, 1, 1, 1};
      if (!PublicDnsWire.auditDatagram(GOOD, ID, peer, new byte[] {1, 0, 0, 1}, 53, false)
              .classification.equals("wrong-source")
          || !PublicDnsWire.auditDatagram(GOOD, ID, peer, peer, 54, false)
              .classification.equals("wrong-source")) {
        throw new AssertionError("Wrong source accepted");
      }
    });
    cases.put("should reject truncated datagram before DNS validation", () -> {
      byte[] peer = {1, 1, 1, 1};
      if (!PublicDnsWire.auditDatagram(GOOD, ID, peer, peer, 53, true)
              .classification.equals("truncated-datagram")) {
        throw new AssertionError("Truncated datagram accepted");
      }
    });
    cases.put("should accept uncompressed mixed case A", () -> {
      byte[] name = hex("074578416d506c4503434f4d00");
      byte[] bytes = concat(hex("123481800001000100000000"), name, hex("00010001"),
          name, hex("000100010000012c0004c0000201"));
      expect(bytes, "usable-a", true, true);
    });
    cases.put("should reject forward pointer question", () -> expect(concat(
        hex("123481800001000100000000c01200010001"),
        hex("076578616d706c6503636f6d00000100010000012c0004c0000201")),
        "malformed", false, false));
    cases.put("should reject wrong ID", () -> expect(changed(GOOD, 0, 0x56), "wrong-identity", false, false));
    cases.put("should reject query QR", () -> expect(changed(GOOD, 2, 0x01), "wrong-identity", false, false));
    cases.put("should reject nonzero opcode", () -> expect(changed(GOOD, 2, 0x89), "wrong-identity", false, false));
    cases.put("should reject wrong question count", () -> expect(changed(GOOD, 5, 2), "wrong-identity", false, false));
    cases.put("should reject wrong question name", () -> expect(changed(GOOD, 13, 'x'), "wrong-identity", false, false));
    cases.put("should reject wrong question type", () -> expect(changed(GOOD, 26, 28), "wrong-identity", false, false));
    cases.put("should reject wrong question class", () -> expect(changed(GOOD, 28, 3), "wrong-identity", false, false));
    cases.put("should distinguish TC", () -> expect(changed(GOOD, 2, 0x83), "tc", false, false));
    cases.put("should distinguish NXDOMAIN SERVFAIL REFUSED", () -> {
      for (int code : new int[] {2, 3, 5}) expect(changed(GOOD, 3, 0x80 | code), "rcode", false, false);
    });
    cases.put("should distinguish no answer", () -> expect(concat(
        hex("123481800001000000000000"), QUESTION), "no-answer", false, false));
    cases.put("should reject out of range pointer", () -> expect(changed(GOOD, 30, 0xff), "malformed", false, false));
    cases.put("should reject compression loop", () -> expect(changed(GOOD, 30, 29), "malformed", false, false));
    cases.put("should reject unsupported label form", () -> expect(changed(GOOD, 12, 0x40), "malformed", false, false));
    cases.put("should reject overlong expanded name", () -> {
      ByteArrayOutputStream name = new ByteArrayOutputStream();
      for (int label = 0; label < 4; label++) {
        name.write(63);
        for (int index = 0; index < 63; index++) name.write('x');
      }
      name.write(0);
      expect(concat(hex("123481800001000100000000"), name.toByteArray(),
          hex("00010001c00c00010001000000000004c0000201")), "malformed", false, false);
    });
    cases.put("should reject every truncated valid prefix", () -> {
      for (int size = 0; size < GOOD.length; size++) {
        expect(Arrays.copyOf(GOOD, size), "malformed", false, false);
      }
    });
    cases.put("should reject trailing bytes", () -> expect(concat(GOOD, new byte[1]), "malformed", false, false));
    cases.put("should distinguish unrelated answer", () -> expect(concat(
        Arrays.copyOf(GOOD, 29), hex("056f7468657203636f6d0000010001000000000004c0000201")),
        "unusable-answer", true, false));
    cases.put("should distinguish wrong answer class", () -> expect(changed(GOOD, 34, 3), "unusable-answer", true, false));
    cases.put("should distinguish wrong answer type", () -> expect(changed(GOOD, 32, 16), "unusable-answer", true, false));
    cases.put("should distinguish invalid A data length", () -> expect(concat(
        changed(Arrays.copyOf(GOOD, GOOD.length - 1), 40, 3)), "unusable-answer", true, false));
    cases.put("should distinguish EDNS extended RCODE", () -> expect(concat(
        changed(GOOD, 11, 1), hex("0000291000010000000000")), "rcode", true, false));
    cases.put("should reject malformed EDNS option", () -> expect(concat(
        changed(GOOD, 11, 1), hex("0000291000000000000003000c00")), "malformed", false, false));
    cases.put("should accept complete CNAME answer chain", () -> {
      byte[] alias = hex("05616c69617303636f6d00");
      expect(concat(hex("123481800001000200000000"), QUESTION,
          hex("c00c000500010000012c000b"), alias,
          alias, hex("000100010000012c0004c0000202")), "usable-a", true, true);
    });
    cases.put("should reject unusable CNAME loop", () -> expect(concat(
        Arrays.copyOf(GOOD, 29), hex("c00c000500010000012c0002c00c")), "unusable-answer", true, false));
    cases.put("should accept complete large answer without MTU cap", () -> {
      ByteArrayOutputStream records = new ByteArrayOutputStream();
      for (int index = 0; index < 300; index++) {
        byte[] record = hex("c00c000100010000012c0004c0000201");
        records.write(record, 0, record.length);
      }
      expect(concat(hex("123481800001012c00000000"), QUESTION, records.toByteArray()),
          "usable-a", true, true);
    });
    return cases;
  }

  private static void golden(int size) {
    byte[] nonce = new byte[32];
    for (int index = 0; index < 32; index++) nonce[index] = (byte) index;
    // Literal independent header/OPT lengths, not offsets or lengths from the implementation.
    String prefix = size == 76
        ? "123401000001000000000001076578616d706c6503636f6d00000100010000291000000000000024000c0020"
        : "123401000001000000000001076578616d706c6503636f6d00000100010000291000000000000fd8000c0fd4";
    byte[] expected = Arrays.copyOf(concat(hex(prefix),
        hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")), size);
    if (!Arrays.equals(expected, PublicDnsWire.query(ID, nonce, size))) {
      throw new AssertionError("Literal query golden differs, size=" + size);
    }
  }

  private static void rejectQuery(int id, int nonce, int size) {
    try {
      PublicDnsWire.query(id, new byte[nonce], size);
    } catch (IllegalArgumentException expected) {
      return;
    }
    throw new AssertionError("Invalid query accepted");
  }

  private static void expect(byte[] bytes, String classification, boolean envelope, boolean usable) {
    PublicDnsWire.Audit result = PublicDnsWire.audit(bytes, ID);
    if (!result.classification.equals(classification) || result.envelopeValid != envelope
        || result.usableA != usable) {
      throw new AssertionError("Expected " + classification + "/" + envelope + "/" + usable
          + ", got " + result.classification + "/" + result.envelopeValid + "/" + result.usableA
          + ": " + result.reason);
    }
    try {
      PublicDnsWire.validateReply(bytes, bytes.length, ID);
      if (!envelope) throw new AssertionError("Legacy success guarantee weakened");
    } catch (IOException rejected) {
      if (envelope) throw new AssertionError("Valid envelope rejected", rejected);
    }
  }

  private static byte[] changed(byte[] bytes, int offset, int value) {
    byte[] copy = bytes.clone();
    copy[offset] = (byte) value;
    return copy;
  }

  private static byte[] concat(byte[]... chunks) {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    for (byte[] chunk : chunks) result.write(chunk, 0, chunk.length);
    return result.toByteArray();
  }

  private static byte[] hex(String text) {
    byte[] bytes = new byte[text.length() / 2];
    for (int index = 0; index < bytes.length; index++) {
      bytes[index] = (byte) Integer.parseInt(text.substring(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }

  public static void main(String[] args) throws IOException {
    Map<String, Runnable> vectors = cases();
    for (Map.Entry<String, Runnable> vector : vectors.entrySet()) {
      vector.getValue().run();
      System.out.println("PASS " + vector.getKey());
    }
    System.out.println("PublicDnsWireVectors passed=" + vectors.size());
    if (args.length == 1) {
      Path directory = Path.of(args[0]);
      byte[] nonce = new byte[32];
      for (int index = 0; index < nonce.length; index++) nonce[index] = (byte) index;
      for (int size : new int[] {76, 4096}) {
        byte[] query = PublicDnsWire.query(ID, nonce, size);
        Files.write(directory.resolve("query-" + size + ".bin"), query, StandardOpenOption.CREATE_NEW);
        System.out.println("query-" + size + ".bin sha256=" + PrivateDnsBytes.digest(query));
      }
      Files.write(directory.resolve("response-good.bin"), GOOD, StandardOpenOption.CREATE_NEW);
    }
  }
}
