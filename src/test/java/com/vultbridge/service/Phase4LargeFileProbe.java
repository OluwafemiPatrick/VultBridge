package com.vultbridge.service;

import com.vultbridge.crypto.PassphraseEncoding;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

/** Runs a generated large-file round trip under the parent test's constrained child heap. */
public final class Phase4LargeFileProbe {
  private static final long GENERATED_BYTES = 96L * 1024 * 1024;

  private Phase4LargeFileProbe() {}

  /**
   * Executes the bounded-memory probe, returning nonzero through the JVM on any failed invariant.
   */
  public static void main(String[] arguments) throws Exception {
    Path directory = Path.of(arguments[0]);
    Path source = directory.resolve("heap-source.bin");
    Path vault = directory.resolve("heap.vltb");
    Path output = directory.resolve("heap-output.bin");
    try (FileChannel channel =
        FileChannel.open(
            source,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.READ,
            StandardOpenOption.WRITE)) {
      channel.position(GENERATED_BYTES - 1);
      channel.write(ByteBuffer.wrap(new byte[] {7}));
    }

    var control = new NeverCancelledControl();
    try (var service = new VaultService();
        var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray())) {
      service.create(vault, passphrase);
      service.importFiles(List.of(source), control);
      service.export("heap-source.bin", output, control);
    }
    if (Files.size(source) != Files.size(output)
        || !java.util.Arrays.equals(digest(source), digest(output))) {
      throw new IllegalStateException("Large-file round trip mismatch");
    }
  }

  private static byte[] digest(Path path) throws Exception {
    var digest = java.security.MessageDigest.getInstance("SHA-256");
    try (var input = Files.newInputStream(path)) {
      byte[] buffer = new byte[8192];
      int read;
      while ((read = input.read(buffer)) >= 0) {
        digest.update(buffer, 0, read);
      }
    }
    return digest.digest();
  }

  private static final class NeverCancelledControl implements VaultOperationControl {
    @Override
    public boolean isCancellationRequested() {
      return false;
    }

    @Override
    public void checkpoint() {}

    @Override
    public void reportProgress(JobProgress progress) {}
  }
}
