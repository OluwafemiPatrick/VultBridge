package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.platform.VaultSidecarLock;
import com.vultbridge.service.CompactionPathPreparer.PreparedCompaction;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies Step 4 streaming candidate construction and preservation of the source vault. */
class VaultCompactorTest {
  private static final String TEMPORARY_CANDIDATE_PREFIX = ".vultbridge-compaction-";

  @TempDir Path temporaryDirectory;

  @Test
  void buildsFreshAuthenticatedRecordsWithCopiedImmutableHeaderAndByteExactContent()
      throws Exception {
    Path sourceVault = temporaryDirectory.resolve("source.vltb");
    Path sourceFile = temporaryDirectory.resolve("source.bin");
    byte[] original = new byte[com.vultbridge.vault.VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES + 1];
    for (int index = 0; index < original.length; index++) {
      original[index] = (byte) (index * 31);
    }
    Files.write(sourceFile, original);

    try (var passphrase = passphrase();
        var source = VaultCreator.create(sourceVault, passphrase)) {
      VaultImporter.importFiles(source, List.of(sourceFile), new NeverCancelledControl());
      VaultSnapshot sourceSnapshot = source.snapshot();
      var operation =
          CompactionOperation.initial(source.vaultPath(), temporaryDirectory, sourceSnapshot);

      try (PreparedCompaction prepared =
          CompactionPathPreparer.prepare(
              operation, java.time.Instant.parse("2026-08-03T12:00:00Z"), () -> 1)) {
        VaultCompactor.CompactionBuild build =
            VaultCompactor.build(
                source, prepared.operation(), prepared.candidate(), new NeverCancelledControl());
        assertEquals(sourceSnapshot.manifest().fileCount(), build.manifest().fileCount());
        assertNotEquals(
            sourceSnapshot.manifest().entries().getFirst().fileRef().recordId(),
            build.manifest().entries().getFirst().fileRef().recordId());

        VaultSnapshot validated =
            VaultCompactor.publishAndValidate(source, prepared, build, new NeverCancelledControl());
        Path compactedVault = prepared.candidate().finalPath();
        assertFalse(Files.exists(prepared.candidate().temporaryPath()));
        assertTrue(Files.exists(compactedVault));
        assertEquals(build.manifest().entries(), validated.manifest().entries());
        assertImmutableHeaderMatches(sourceVault, compactedVault);

        try (var reopened = VaultUnlocker.open(compactedVault, passphrase)) {
          Path exported = temporaryDirectory.resolve("reopened.bin");
          VaultExporter.export(reopened, "source.bin", exported, new NeverCancelledControl());
          assertArrayEquals(original, Files.readAllBytes(exported));
        }
      }
    }
  }

  @Test
  void cancellationBeforeCopyLeavesSourceUsableAndCandidateUnpublished() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("cancel-source.vltb");
    Path sourceFile = temporaryDirectory.resolve("cancel.bin");
    Files.write(sourceFile, new byte[] {4, 5, 6});
    try (var passphrase = passphrase();
        var source = VaultCreator.create(sourceVault, passphrase)) {
      VaultImporter.importFiles(source, List.of(sourceFile), new NeverCancelledControl());
      VaultSnapshot before = source.snapshot();
      var operation = CompactionOperation.initial(source.vaultPath(), temporaryDirectory, before);
      try (PreparedCompaction prepared =
          CompactionPathPreparer.prepare(
              operation, java.time.Instant.parse("2026-08-03T12:00:00Z"), () -> 2)) {
        try {
          VaultCompactor.build(
              source, prepared.operation(), prepared.candidate(), new CancelledControl());
        } catch (JobCancelledException expected) {
          // Expected safe cancellation before any candidate commit is installed.
        }
        assertFalse(Files.exists(prepared.operation().finalOutputPath().orElseThrow()));
        assertTrue(Files.exists(sourceVault));
        assertEquals(before.manifest(), source.snapshot().manifest());
      }
      assertNoTemporaryCandidates();
    }
  }

  @Test
  void validationFailureRemovesOnlyThePublishedCandidateAndPreservesSource() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("tamper-source.vltb");
    Path sourceFile = temporaryDirectory.resolve("tamper.bin");
    Files.write(sourceFile, new byte[] {7, 8, 9});
    try (var passphrase = passphrase();
        var source = VaultCreator.create(sourceVault, passphrase)) {
      VaultImporter.importFiles(source, List.of(sourceFile), new NeverCancelledControl());
      var operation =
          CompactionOperation.initial(source.vaultPath(), temporaryDirectory, source.snapshot());
      try (PreparedCompaction prepared =
          CompactionPathPreparer.prepare(
              operation, java.time.Instant.parse("2026-08-03T12:00:00Z"), () -> 3)) {
        VaultCompactor.CompactionBuild build =
            VaultCompactor.build(
                source, prepared.operation(), prepared.candidate(), new NeverCancelledControl());
        long ciphertextOffset =
            build.manifest().entries().getFirst().fileRef().offset()
                + com.vultbridge.vault.VaultFormat.RECORD_FRAME_HEADER_BYTES;
        prepared
            .candidate()
            .write(
                channel -> {
                  ByteBuffer originalByte = ByteBuffer.allocate(1);
                  channel.read(originalByte, ciphertextOffset);
                  channel.write(
                      ByteBuffer.wrap(new byte[] {(byte) (originalByte.array()[0] ^ 1)}),
                      ciphertextOffset);
                });

        assertThrowsSanitizedValidationFailure(
            () ->
                VaultCompactor.publishAndValidate(
                    source, prepared, build, new NeverCancelledControl()));
        assertFalse(Files.exists(prepared.candidate().finalPath()));
        assertTrue(Files.exists(sourceVault));
      }
    }
  }

  @Test
  void validationRejectsChangedImmutableHeaderAndPreservesSource() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("header-source.vltb");
    Path sourceFile = temporaryDirectory.resolve("header.bin");
    Files.write(sourceFile, new byte[] {1, 2, 3});
    try (var passphrase = passphrase();
        var source = VaultCreator.create(sourceVault, passphrase)) {
      VaultImporter.importFiles(source, List.of(sourceFile), new NeverCancelledControl());
      var operation =
          CompactionOperation.initial(source.vaultPath(), temporaryDirectory, source.snapshot());
      try (PreparedCompaction prepared =
          CompactionPathPreparer.prepare(
              operation, java.time.Instant.parse("2026-08-03T12:00:00Z"), () -> 4)) {
        VaultCompactor.CompactionBuild build =
            VaultCompactor.build(
                source, prepared.operation(), prepared.candidate(), new NeverCancelledControl());
        long wrapNonceOffset =
            com.vultbridge.vault.VaultFormat.PRELUDE_BYTES
                + com.vultbridge.vault.VaultFormat.VAULT_ID_BYTES
                + 1L
                + 1L
                + 4L
                + 4L
                + 4L
                + com.vultbridge.vault.VaultFormat.KDF_SALT_BYTES;
        prepared
            .candidate()
            .write(
                channel -> {
                  ByteBuffer originalByte = ByteBuffer.allocate(1);
                  channel.read(originalByte, wrapNonceOffset);
                  channel.write(
                      ByteBuffer.wrap(new byte[] {(byte) (originalByte.array()[0] ^ 1)}),
                      wrapNonceOffset);
                });

        assertThrowsSanitizedValidationFailure(
            () ->
                VaultCompactor.publishAndValidate(
                    source, prepared, build, new NeverCancelledControl()));
        assertFalse(Files.exists(prepared.candidate().finalPath()));
        assertTrue(Files.exists(sourceVault));
      }
    }
  }

  @Test
  void validationLockContentionRetainsPublishedOutputAndReportsLockFailure() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("lock-source.vltb");
    Path sourceFile = temporaryDirectory.resolve("lock.bin");
    Files.write(sourceFile, new byte[] {4, 5, 6});
    try (var passphrase = passphrase();
        var source = VaultCreator.create(sourceVault, passphrase)) {
      VaultImporter.importFiles(source, List.of(sourceFile), new NeverCancelledControl());
      var operation =
          CompactionOperation.initial(source.vaultPath(), temporaryDirectory, source.snapshot());
      try (PreparedCompaction prepared =
              CompactionPathPreparer.prepare(
                  operation, java.time.Instant.parse("2026-08-03T12:00:00Z"), () -> 5);
          VaultSidecarLock competingLock =
              VaultSidecarLock.acquire(prepared.candidate().finalPath())) {
        assertTrue(competingLock.isOpen());
        VaultCompactor.CompactionBuild build =
            VaultCompactor.build(
                source, prepared.operation(), prepared.candidate(), new NeverCancelledControl());
        var failure =
            org.junit.jupiter.api.Assertions.assertThrows(
                VaultOperationException.class,
                () ->
                    VaultCompactor.publishAndValidate(
                        source, prepared, build, new NeverCancelledControl()));
        assertEquals(JobFailureCategory.VAULT_ALREADY_OPEN, failure.category());
        assertTrue(Files.exists(prepared.candidate().finalPath()));
        assertTrue(Files.exists(sourceVault));
      }
    }
  }

  @Test
  void cancellationAfterACompletedChunkLeavesSourceUsableAndCandidateUnpublished()
      throws Exception {
    Path sourceVault = temporaryDirectory.resolve("chunk-cancel-source.vltb");
    Path sourceFile = temporaryDirectory.resolve("chunk-cancel.bin");
    Files.write(
        sourceFile, new byte[com.vultbridge.vault.VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES + 1]);
    try (var passphrase = passphrase();
        var source = VaultCreator.create(sourceVault, passphrase)) {
      VaultImporter.importFiles(source, List.of(sourceFile), new NeverCancelledControl());
      VaultSnapshot before = source.snapshot();
      var operation = CompactionOperation.initial(source.vaultPath(), temporaryDirectory, before);
      try (PreparedCompaction prepared =
          CompactionPathPreparer.prepare(
              operation, java.time.Instant.parse("2026-08-03T12:00:00Z"), () -> 6)) {
        assertThrows(
            JobCancelledException.class,
            () ->
                VaultCompactor.build(
                    source,
                    prepared.operation(),
                    prepared.candidate(),
                    new CancelAfterChunkControl()));
        assertFalse(Files.exists(prepared.candidate().finalPath()));
        assertTrue(Files.exists(sourceVault));
        assertEquals(before.manifest(), source.snapshot().manifest());
      }
      assertNoTemporaryCandidates();
    }
  }

  private static void assertThrowsSanitizedValidationFailure(ThrowingOperation operation)
      throws Exception {
    var failure =
        org.junit.jupiter.api.Assertions.assertThrows(
            VaultOperationException.class, operation::run);
    assertEquals(JobFailureCategory.SECURITY, failure.category());
  }

  private void assertImmutableHeaderMatches(Path source, Path compacted) throws Exception {
    byte[] sourceHeader = Files.readAllBytes(source);
    byte[] compactedHeader = Files.readAllBytes(compacted);
    assertArrayEquals(
        java.util.Arrays.copyOf(
            sourceHeader,
            com.vultbridge.vault.VaultFormat.IMMUTABLE_HEADER_BYTES
                + com.vultbridge.vault.VaultFormat.PRELUDE_BYTES),
        java.util.Arrays.copyOf(
            compactedHeader,
            com.vultbridge.vault.VaultFormat.IMMUTABLE_HEADER_BYTES
                + com.vultbridge.vault.VaultFormat.PRELUDE_BYTES));
  }

  private void assertNoTemporaryCandidates() throws Exception {
    try (var paths = Files.list(temporaryDirectory)) {
      assertTrue(
          paths.noneMatch(
              path -> {
                Path fileName = path.getFileName();
                return fileName != null
                    && fileName.toString().startsWith(TEMPORARY_CANDIDATE_PREFIX);
              }));
    }
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return PassphraseEncoding.encode("correct horse battery staple".toCharArray());
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

  private static final class CancelledControl implements VaultOperationControl {
    @Override
    public boolean isCancellationRequested() {
      return true;
    }

    @Override
    public void checkpoint() throws JobCancelledException {
      throw new JobCancelledException();
    }

    @Override
    public void reportProgress(JobProgress progress) throws JobCancelledException {
      throw new JobCancelledException();
    }
  }

  private static final class CancelAfterChunkControl implements VaultOperationControl {
    private int cancellationChecks;

    @Override
    public boolean isCancellationRequested() {
      return cancellationChecks++ > 0;
    }

    @Override
    public void checkpoint() {}

    @Override
    public void reportProgress(JobProgress progress) {}
  }

  @FunctionalInterface
  private interface ThrowingOperation {
    void run() throws Exception;
  }
}
