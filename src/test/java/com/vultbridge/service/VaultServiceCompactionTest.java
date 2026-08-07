package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.platform.VaultSidecarLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies the complete service-owned Step 6 source replacement lifecycle. */
class VaultServiceCompactionTest {
  private static final String TEMPORARY_CANDIDATE_PREFIX = ".vultbridge-compaction-";

  @TempDir Path temporaryDirectory;

  @Test
  void removesSourceAfterValidationAndRetainsAnUnlockedReplacementSession() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("source.vltb");
    Path keep = temporaryDirectory.resolve("keep.bin");
    Path removed = temporaryDirectory.resolve("removed.bin");
    byte[] keepBytes = {1, 2, 3, 4};
    Files.write(keep, keepBytes);
    Files.write(removed, new byte[] {9, 8, 7});

    Path compactedVault;
    try (var service = new VaultService();
        var passphrase = passphrase()) {
      service.create(sourceVault, passphrase);
      service.importFiles(List.of(keep, removed), new NeverCancelledControl());
      service.delete("removed.bin", new NeverCancelledControl());

      CompactionPreview preview = service.previewCompaction(temporaryDirectory);
      assertTrue(preview.outputFileName().matches("source-\\d{8}T\\d{6}Z-[0-9a-f]{6}\\.vltb"));
      CompactionResult result =
          service.compact(temporaryDirectory, preview, new NeverCancelledControl());
      assertEquals(CompactionOutcome.COMPLETED_SOURCE_RETAINED, result.outcome());
      compactedVault =
          temporaryDirectory.resolve(result.resultingVault().orElseThrow().vaultDisplayName());
      assertEquals(
          preview.outputFileName(), result.resultingVault().orElseThrow().vaultDisplayName());
      assertEquals(preview.estimate().estimatedCandidateBytes(), Files.size(compactedVault));
      assertTrue(Files.exists(sourceVault));
      assertTrue(Files.exists(compactedVault));
      assertTrue(service.isOpen());

      Path exported = temporaryDirectory.resolve("after-compaction.bin");
      service.export("keep.bin", exported, new NeverCancelledControl());
      assertArrayEquals(keepBytes, Files.readAllBytes(exported));
      assertEquals(1, service.snapshot().manifest().fileCount());
      service.lock();
    }

    try (var service = new VaultService();
        var passphrase = passphrase()) {
      assertEquals(1, service.open(compactedVault, passphrase).manifest().fileCount());
    }

    try (var wrongPassphrase = passphrase("wrong horse battery staple")) {
      assertThrows(
          UnableToUnlockVaultException.class,
          () -> VaultUnlocker.open(compactedVault, wrongPassphrase));
    }

    long compactedSize = Files.size(compactedVault);
    try (var channel =
        java.nio.channels.FileChannel.open(compactedVault, StandardOpenOption.WRITE)) {
      channel.truncate(compactedSize - 1);
    }
    try (var passphrase = passphrase()) {
      assertThrows(
          UnableToUnlockVaultException.class, () -> VaultUnlocker.open(compactedVault, passphrase));
    }
  }

  @Test
  void cancellationBeforeCandidateBuildLeavesSourceAndSessionUsable() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("cancel-source.vltb");
    Path source = temporaryDirectory.resolve("cancel.bin");
    Files.write(source, new byte[] {5, 6, 7});
    try (var service = new VaultService();
        var passphrase = passphrase()) {
      service.create(sourceVault, passphrase);
      service.importFiles(List.of(source), new NeverCancelledControl());
      VaultSnapshot before = service.snapshot();

      assertThrows(
          JobCancelledException.class,
          () -> service.compact(temporaryDirectory, new CancelledControl()));
      assertTrue(Files.exists(sourceVault));
      assertTrue(service.isOpen());
      assertEquals(before.manifest().fileCount(), service.snapshot().manifest().fileCount());
      assertNoTemporaryCandidates();
    }
  }

  @Test
  void reportsValidatedReplacementWhenSourceRemovalFails() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("retained-source.vltb");
    Path source = temporaryDirectory.resolve("retained.bin");
    Files.write(source, new byte[] {1, 2, 3});
    try (var service =
            new VaultService(
                path -> {
                  throw new java.io.IOException("injected");
                });
        var passphrase = passphrase()) {
      service.create(sourceVault, passphrase);
      service.importFiles(List.of(source), new NeverCancelledControl());

      CompactionResult result = service.compact(temporaryDirectory, new NeverCancelledControl());

      assertEquals(CompactionOutcome.COMPLETED_SOURCE_RETAINED, result.outcome());
      assertTrue(Files.exists(sourceVault));
      Path replacement =
          temporaryDirectory.resolve(result.resultingVault().orElseThrow().vaultDisplayName());
      assertTrue(Files.exists(replacement));
      assertTrue(service.isOpen());
      assertEquals(1, service.snapshot().manifest().fileCount());
    }
  }

  @Test
  void holdsSourceLockThroughIdentityCheckAndRemoval() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("locked-removal-source.vltb");
    Path source = temporaryDirectory.resolve("locked-removal.bin");
    Files.write(source, new byte[] {1, 2, 3});
    AtomicBoolean sourceLockWasHeld = new AtomicBoolean();
    CompactionSourceRemover remover =
        path -> {
          try {
            VaultSidecarLock.acquire(path).close();
          } catch (com.vultbridge.platform.VaultAlreadyOpenException exception) {
            sourceLockWasHeld.set(true);
          } catch (com.vultbridge.platform.VaultAccessException exception) {
            throw new java.io.IOException("Source lock could not be checked", exception);
          }
          Files.delete(path);
          return true;
        };

    try (var service = new VaultService(remover);
        var passphrase = passphrase()) {
      service.create(sourceVault, passphrase);
      service.importFiles(List.of(source), new NeverCancelledControl());

      CompactionResult result = service.compact(temporaryDirectory, new NeverCancelledControl());

      assertEquals(CompactionOutcome.COMPLETED_SOURCE_REMOVED, result.outcome());
      assertTrue(sourceLockWasHeld.get());
      assertFalse(Files.exists(sourceVault));
    }
  }

  @Test
  void rejectsAReplacementAtTheRetainedSourcePathByFileIdentity() throws Exception {
    Path sourceVault = temporaryDirectory.resolve("identity-source.vltb");
    try (var passphrase = passphrase();
        var session = VaultCreator.create(sourceVault, passphrase)) {
      Path moved = temporaryDirectory.resolve("identity-moved.vltb");
      Files.move(sourceVault, moved);
      Files.write(sourceVault, new byte[] {9});

      assertFalse(session.sourceIdentityMatches());
    }
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
    return passphrase("correct horse battery staple");
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase(String value) {
    return PassphraseEncoding.encode(value.toCharArray());
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
}
