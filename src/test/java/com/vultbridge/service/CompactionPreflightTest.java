package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies read-only compaction preflight against an authenticated live vault. */
class CompactionPreflightTest {
  private static final String TEMPORARY_CANDIDATE_PREFIX = ".vultbridge-compaction-";

  @TempDir Path temporaryDirectory;

  @Test
  void reportsPhysicalAndAuthenticatedLiveTotalsWithoutCreatingCandidates() throws Exception {
    Path vault = temporaryDirectory.resolve("source.vltb");
    Path source = temporaryDirectory.resolve("source.bin");
    Files.write(source, new byte[] {1, 2, 3, 4});
    try (var service = new VaultService();
        var passphrase = passphrase()) {
      service.create(vault, passphrase);
      service.importFiles(List.of(source), new NeverCancelledControl());

      CompactionStorageEstimate estimate = service.preflightCompaction(temporaryDirectory);

      assertEquals(Files.size(vault), estimate.sourcePhysicalVaultBytes());
      assertEquals(4, estimate.liveLogicalFileBytes());
      assertEquals(1, estimate.fileCount());
      assertTrue(estimate.estimatedCandidateBytes() > 0);
      assertEquals(
          estimate.estimatedCandidateBytes() + estimate.safetyMarginBytes(),
          estimate.requiredDestinationBytes());
      assertTrue(estimate.hasSufficientSpace());
      assertNoTemporaryCandidates();
    }
  }

  @Test
  void refusesInsufficientSpaceBeforeAnyCandidateMutation() throws Exception {
    var estimate = new CompactionStorageEstimate(100, 80, 1, 200, 4, 204, 203);

    assertTrue(!estimate.hasSufficientSpace());
    org.junit.jupiter.api.Assertions.assertThrows(
        java.io.IOException.class, () -> CompactionPreflight.requireSufficientSpace(estimate));
  }

  @Test
  void estimatesAnEmptyAuthenticatedVaultWithoutCreatingAFile() throws Exception {
    Path vault = temporaryDirectory.resolve("empty.vltb");
    try (var service = new VaultService();
        var passphrase = passphrase()) {
      service.create(vault, passphrase);

      CompactionStorageEstimate estimate = service.preflightCompaction(temporaryDirectory);

      assertEquals(0, estimate.liveLogicalFileBytes());
      assertEquals(0, estimate.fileCount());
      assertTrue(
          estimate.estimatedCandidateBytes()
              >= com.vultbridge.vault.VaultFormat.FIXED_HEADER_BYTES);
      assertNoTemporaryCandidates();
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
}
