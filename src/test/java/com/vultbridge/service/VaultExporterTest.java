package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies byte-exact authenticated export and destination non-overwrite policy. */
class VaultExporterTest {
  @TempDir Path temporaryDirectory;

  @Test
  void exportsBytesExactlyAndLeavesVaultMetadataUnchanged() throws Exception {
    Path vault = temporaryDirectory.resolve("export.vltb");
    Path source = temporaryDirectory.resolve("source.bin");
    Path destination = temporaryDirectory.resolve("destination.bin");
    byte[] original = new byte[1024];
    for (int index = 0; index < original.length; index++) {
      original[index] = (byte) (index * 13);
    }
    Files.write(source, original);

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultImporter.importFiles(session, List.of(source), new NeverCancelledControl());
      VaultExporter.export(session, "source.bin", destination, new NeverCancelledControl());
      assertEquals(1, session.manifest().fileCount());
    }
    assertArrayEquals(original, Files.readAllBytes(destination));
  }

  @Test
  void rejectsExistingDestinationAndMissingSelection() throws Exception {
    Path vault = temporaryDirectory.resolve("reject-export.vltb");
    Path destination = temporaryDirectory.resolve("existing.bin");
    Files.write(destination, new byte[] {9});
    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultOperationException missing =
          assertThrows(
              VaultOperationException.class,
              () ->
                  VaultExporter.export(
                      session, "missing.bin", destination, new NeverCancelledControl()));
      assertEquals(JobFailureCategory.INPUT_REJECTED, missing.category());
    }
    assertArrayEquals(new byte[] {9}, Files.readAllBytes(destination));
    assertFalse(Files.exists(temporaryDirectory.resolve("missing.bin")));
  }

  @Test
  void existingAndSymbolicDestinationsRemainUnchangedForAValidSelection() throws Exception {
    Path vault = temporaryDirectory.resolve("destination-policy.vltb");
    Path source = temporaryDirectory.resolve("selected.bin");
    Path existing = temporaryDirectory.resolve("existing-selected.bin");
    Path symbolic = temporaryDirectory.resolve("symbolic-selected.bin");
    Files.write(source, new byte[] {1});
    Files.write(existing, new byte[] {9});
    Files.createSymbolicLink(symbolic, existing.getFileName());

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultImporter.importFiles(session, List.of(source), new NeverCancelledControl());
      for (Path destination : List.of(existing, symbolic)) {
        VaultOperationException failure =
            assertThrows(
                VaultOperationException.class,
                () ->
                    VaultExporter.export(
                        session, "selected.bin", destination, new NeverCancelledControl()));
        assertEquals(JobFailureCategory.FILESYSTEM, failure.category());
      }
    }
    assertArrayEquals(new byte[] {9}, Files.readAllBytes(existing));
    assertNoExportTemporaries();
  }

  @Test
  void tamperedChunkNeverBecomesACompletedOutput() throws Exception {
    Path vault = temporaryDirectory.resolve("tampered-export.vltb");
    Path source = temporaryDirectory.resolve("tamper-source.bin");
    Path destination = temporaryDirectory.resolve("tampered-output.bin");
    Files.write(source, new byte[] {1, 2, 3});

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultImporter.importFiles(session, List.of(source), new NeverCancelledControl());
      var reference = session.manifest().entries().getFirst().fileRef();
      long changedOffset = reference.endOffset() - 1;
      ByteBuffer original = ByteBuffer.allocate(1);
      assertEquals(1, session.channel().read(original, changedOffset));
      original.array()[0] ^= 1;
      assertEquals(1, session.channel().write(ByteBuffer.wrap(original.array()), changedOffset));

      VaultOperationException failure =
          assertThrows(
              VaultOperationException.class,
              () ->
                  VaultExporter.export(
                      session, "tamper-source.bin", destination, new NeverCancelledControl()));
      assertEquals(JobFailureCategory.SECURITY, failure.category());
      assertEquals(1, session.manifest().fileCount());
    }
    assertFalse(Files.exists(destination));
    assertNoExportTemporaries();
  }

  @Test
  void cancellationBetweenChunksRemovesPartialPlaintext() throws Exception {
    Path vault = temporaryDirectory.resolve("cancel-export.vltb");
    Path source = temporaryDirectory.resolve("large-source.bin");
    Path destination = temporaryDirectory.resolve("cancelled-output.bin");
    try (var sourceChannel =
        java.nio.channels.FileChannel.open(
            source,
            java.nio.file.StandardOpenOption.CREATE_NEW,
            java.nio.file.StandardOpenOption.READ,
            java.nio.file.StandardOpenOption.WRITE)) {
      sourceChannel.position(com.vultbridge.vault.VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES);
      sourceChannel.write(ByteBuffer.wrap(new byte[] {1}));
    }
    var checks = new AtomicInteger();
    VaultOperationControl cancelling =
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

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultImporter.importFiles(session, List.of(source), new NeverCancelledControl());
      assertThrows(
          CancellationException.class,
          () -> VaultExporter.export(session, "large-source.bin", destination, cancelling));
      assertEquals(1, session.manifest().fileCount());
    }
    assertFalse(Files.exists(destination));
    assertNoExportTemporaries();
  }

  private void assertNoExportTemporaries() throws Exception {
    try (var paths = Files.list(temporaryDirectory)) {
      assertTrue(paths.noneMatch(path -> path.toString().contains(".vultbridge-export-")));
    }
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
