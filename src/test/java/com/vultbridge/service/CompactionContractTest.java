package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.vault.VaultManifest;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies the Phase 5 service contracts without creating or mutating a compaction candidate. */
class CompactionContractTest {
  @TempDir Path temporaryDirectory;

  private static final VaultSnapshot SOURCE_SNAPSHOT =
      new VaultSnapshot("source.vltb", new VaultManifest(java.util.List.of()), 282);

  @Test
  void initialOperationCarriesOnlyServiceOwnedSourceAndAuthenticatedMetadata() {
    Path source = Path.of("source.vltb");
    Path destination = Path.of("backups");

    CompactionOperation operation =
        CompactionOperation.initial(source, destination, SOURCE_SNAPSHOT);

    assertEquals(source.toAbsolutePath().normalize(), operation.sourceVaultPath());
    assertEquals(destination.toAbsolutePath().normalize(), operation.destinationDirectory());
    assertEquals(Optional.empty(), operation.finalOutputPath());
    assertEquals(Optional.empty(), operation.candidatePath());
    assertEquals(SOURCE_SNAPSHOT, operation.sourceSnapshot());
    assertEquals(0, operation.liveLogicalFileBytes());
    assertEquals(0, operation.fileCount());
    assertEquals(new JobProgress(JobPhase.PREPARING, 0, 0), operation.progress());
  }

  @Test
  void serviceCapturesTheOpenSessionPathWithoutAddingItToTheSnapshot() throws Exception {
    Path source = temporaryDirectory.resolve("service-contract.vltb");
    try (var service = new VaultService();
        var passphrase = passphrase()) {
      VaultSnapshot snapshot = service.create(source, passphrase);
      CompactionOperation operation = service.prepareCompaction(Path.of("destination"));

      assertEquals(source.toAbsolutePath().normalize(), operation.sourceVaultPath());
      assertEquals(snapshot, operation.sourceSnapshot());
      assertFalse(
          operation.sourceSnapshot().toString().contains(source.toAbsolutePath().toString()));
    }
  }

  @Test
  void completedResultsDistinguishSourceRemovalFromRetainedSource() {
    CompactionResult removed = CompactionResult.completed(true, SOURCE_SNAPSHOT);
    CompactionResult retained = CompactionResult.completed(false, SOURCE_SNAPSHOT);

    assertEquals(CompactionOutcome.COMPLETED_SOURCE_REMOVED, removed.outcome());
    assertEquals(CompactionOutcome.COMPLETED_SOURCE_RETAINED, retained.outcome());
    assertEquals(Optional.of(SOURCE_SNAPSHOT), removed.resultingVault());
    assertTrue(removed.failureCategory().isEmpty());
    assertTrue(retained.failureCategory().isEmpty());
  }

  @Test
  void cancellationAndExpectedFailureRetainTheSource() {
    CompactionResult cancelled = CompactionResult.cancelled();
    CompactionResult failed = CompactionResult.failed(JobFailureCategory.FILESYSTEM);

    assertEquals(CompactionOutcome.CANCELLED_SOURCE_RETAINED, cancelled.outcome());
    assertEquals(CompactionOutcome.FAILED_SOURCE_RETAINED, failed.outcome());
    assertTrue(cancelled.resultingVault().isEmpty());
    assertEquals(Optional.of(JobFailureCategory.FILESYSTEM), failed.failureCategory());
  }

  @Test
  void resultRejectsInconsistentOutcomePayloads() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new CompactionResult(
                CompactionOutcome.COMPLETED_SOURCE_REMOVED, Optional.empty(), Optional.empty()));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new CompactionResult(
                CompactionOutcome.FAILED_SOURCE_RETAINED, Optional.empty(), Optional.empty()));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new CompactionResult(
                CompactionOutcome.CANCELLED_SOURCE_RETAINED,
                Optional.empty(),
                Optional.of(JobFailureCategory.FILESYSTEM)));
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return com.vultbridge.crypto.PassphraseEncoding.encode(
        "correct horse battery staple".toCharArray());
  }
}
