package net.mullvad.mullvadvpn.test.publicdns;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/** Immutable per-attempt files below an Android application's private files directory. */
public final class PrivateDnsBytes {
  public final File directory;

  public PrivateDnsBytes(File privateFiles) throws IOException {
    File root = new File(privateFiles, "public-dns");
    if (!root.isDirectory() && !root.mkdir()) throw new IOException("Cannot create private DNS root");
    directory = new File(root, UUID.randomUUID().toString());
    if (!directory.mkdir()) throw new IOException("Cannot create private DNS attempt");
  }

  public static final class Saved {
    public final String path;
    public final int size;
    public final String sha256;

    private Saved(File file, byte[] bytes) {
      path = file.getAbsolutePath();
      size = bytes.length;
      sha256 = digest(bytes);
    }
  }

  public Saved save(String name, byte[] bytes) throws IOException {
    if (!name.matches("[a-z][a-z0-9-]*\\.(bin|json)")) {
      throw new IllegalArgumentException("Private DNS artifact name");
    }
    File file = new File(directory, name);
    if (!file.createNewFile()) throw new IOException("DNS evidence already exists");
    try (FileOutputStream output = new FileOutputStream(file)) {
      output.write(bytes);
      output.getFD().sync();
    }
    return new Saved(file, bytes);
  }

  public static String digest(byte[] bytes) {
    try {
      StringBuilder result = new StringBuilder(64);
      for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) {
        result.append("0123456789abcdef".charAt((value & 255) >>> 4));
        result.append("0123456789abcdef".charAt(value & 15));
      }
      return result.toString();
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }
}
