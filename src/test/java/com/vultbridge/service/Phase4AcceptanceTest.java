package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.vault.FileRecordLayout;
import com.vultbridge.vault.VaultFormat;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the Phase 4 import/export exit gate across failure and streaming boundaries. */
class Phase4AcceptanceTest {
  @TempDir Path temporaryDirectory;

  @Test
  void emptyAndMultiChunkFilesRoundTripWithoutChangingSources() throws Exception {
    Path vault = temporaryDirectory.resolve("roundtrip.vltb");
    Path empty = temporaryDirectory.resolve("empty.bin");
    Path large = temporaryDirectory.resolve("large.bin");
    Files.createFile(empty);
    byte[] original = new byte[VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES + 29];
    for (int index = 0; index < original.length; index++) {
      original[index] = (byte) (index * 7);
    }
    Files.write(large, original);
    byte[] sourceDigest = digest(large);

    try (var service = new VaultService();
        var passphrase = passphrase()) {
      service.create(vault, passphrase);
      VaultSnapshot imported =
          service.importFiles(List.of(empty, large), new NeverCancelledControl());
      assertEquals(2, imported.manifest().fileCount());
      service.export(
          "empty.bin", temporaryDirectory.resolve("empty-output.bin"), new NeverCancelledControl());
      service.export(
          "large.bin", temporaryDirectory.resolve("large-output.bin"), new NeverCancelledControl());
    }

    assertEquals(0, Files.size(temporaryDirectory.resolve("empty-output.bin")));
    assertArrayEquals(original, Files.readAllBytes(temporaryDirectory.resolve("large-output.bin")));
    assertArrayEquals(sourceDigest, digest(large));
  }

  @Test
  void copiedClosedVaultUnlocksAndExportsIndependently() throws Exception {
    Path originalVault = temporaryDirectory.resolve("original.vltb");
    Path backupVault = temporaryDirectory.resolve("backup.vltb");
    Path source = temporaryDirectory.resolve("backup-source.bin");
    Path exported = temporaryDirectory.resolve("backup-output.bin");
    byte[] original = new byte[] {3, 1, 4, 1, 5, 9};
    Files.write(source, original);

    try (var service = new VaultService();
        var passphrase = passphrase()) {
      service.create(originalVault, passphrase);
      service.importFiles(List.of(source), new NeverCancelledControl());
      service.lock();
    }
    Files.copy(originalVault, backupVault);

    try (var service = new VaultService();
        var passphrase = passphrase()) {
      assertEquals(1, service.open(backupVault, passphrase).manifest().fileCount());
      service.export("backup-source.bin", exported, new NeverCancelledControl());
    }

    assertArrayEquals(original, Files.readAllBytes(exported));
  }

  @Test
  void cancelledImportLeavesNoManifestEntryAfterReopen() throws Exception {
    Path vault = temporaryDirectory.resolve("cancel-import.vltb");
    Path source = temporaryDirectory.resolve("cancel-source.bin");
    try (var channel =
        FileChannel.open(
            source,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.READ,
            StandardOpenOption.WRITE)) {
      channel.position(VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES);
      channel.write(ByteBuffer.wrap(new byte[] {1}));
    }
    var checks = new AtomicInteger();
    VaultOperationControl cancellation =
        new VaultOperationControl() {
          @Override
          public boolean isCancellationRequested() {
            return checks.incrementAndGet() > 1;
          }

          @Override
          public void checkpoint() {}

          @Override
          public void reportProgress(JobProgress progress) {}
        };

    try (var service = new VaultService();
        var passphrase = passphrase()) {
      service.create(vault, passphrase);
      assertThrows(
          CancellationException.class, () -> service.importFiles(List.of(source), cancellation));
    }

    try (var service = new VaultService();
        var passphrase = passphrase()) {
      assertEquals(0, service.open(vault, passphrase).manifest().fileCount());
    }
  }

  @Test
  void laterChunkTamperingRemovesPartialPlaintextOutput() throws Exception {
    Path vault = temporaryDirectory.resolve("later-tamper.vltb");
    Path source = temporaryDirectory.resolve("later-source.bin");
    Path destination = temporaryDirectory.resolve("later-output.bin");
    try (var channel =
        FileChannel.open(
            source,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.READ,
            StandardOpenOption.WRITE)) {
      channel.position(VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES);
      channel.write(ByteBuffer.wrap(new byte[] {7}));
    }

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultImporter.importFiles(session, List.of(source), new NeverCancelledControl());
      var entry = session.manifest().entries().getFirst();
      FileRecordLayout layout = FileRecordLayout.forLogicalSize(entry.logicalSize());
      long secondChunkTag =
          entry.fileRef().offset()
              + VaultFormat.RECORD_FRAME_HEADER_BYTES
              + layout.chunkStoredOffset(1)
              + layout.chunkPlaintextLength(1)
              + VaultFormat.AEAD_TAG_BYTES
              - 1;
      mutateByte(session.channel(), secondChunkTag);

      VaultOperationException failure =
          assertThrows(
              VaultOperationException.class,
              () ->
                  VaultExporter.export(
                      session, "later-source.bin", destination, new NeverCancelledControl()));
      assertEquals(JobFailureCategory.SECURITY, failure.category());
    }
    assertFalse(Files.exists(destination));
    assertNoExportTemporaries();
  }

  @Test
  void mutatedPublicFileIdAndLengthFailBeforeCompletedExport() throws Exception {
    Path vault = temporaryDirectory.resolve("frame-tamper.vltb");
    Path source = temporaryDirectory.resolve("frame-source.bin");
    Files.write(source, new byte[] {1, 2, 3});

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultImporter.importFiles(session, List.of(source), new NeverCancelledControl());
      long frameOffset = session.manifest().entries().getFirst().fileRef().offset();
      for (long mutationOffset :
          new long[] {frameOffset, frameOffset + VaultFormat.RECORD_ID_BYTES + Long.BYTES - 1}) {
        mutateByte(session.channel(), mutationOffset);
        Path destination = temporaryDirectory.resolve("frame-output-" + mutationOffset + ".bin");
        VaultOperationException failure =
            assertThrows(
                VaultOperationException.class,
                () ->
                    VaultExporter.export(
                        session, "frame-source.bin", destination, new NeverCancelledControl()));
        assertEquals(JobFailureCategory.SECURITY, failure.category());
        assertFalse(Files.exists(destination));
        mutateByte(session.channel(), mutationOffset);
      }
    }
    assertNoExportTemporaries();
  }

  @Test
  void largeGeneratedRoundTripCompletesUnderConstrainedHeap() throws Exception {
    Process process =
        new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx160m",
                "-cp",
                System.getProperty("java.class.path"),
                "com.vultbridge.service.Phase4LargeFileProbe",
                temporaryDirectory.toString())
            .start();
    boolean completed = process.waitFor(120, java.util.concurrent.TimeUnit.SECONDS);
    if (!completed) {
      process.destroyForcibly();
    }
    String error =
        new String(
            process.getErrorStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    assertTrue(completed, "Large-file probe timed out");
    assertEquals(0, process.exitValue(), error);
  }

  private void assertNoExportTemporaries() throws Exception {
    try (var paths = Files.list(temporaryDirectory)) {
      assertTrue(paths.noneMatch(path -> path.toString().contains(".vultbridge-export-")));
    }
  }

  private static void mutateByte(FileChannel channel, long offset) throws Exception {
    ByteBuffer value = ByteBuffer.allocate(1);
    if (channel.read(value, offset) != 1) {
      throw new IllegalStateException("Unable to read mutation byte");
    }
    value.array()[0] ^= 1;
    if (channel.write(ByteBuffer.wrap(value.array()), offset) != 1) {
      throw new IllegalStateException("Unable to write mutation byte");
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

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return PassphraseEncoding.encode("correct horse battery staple".toCharArray());
  }
}
