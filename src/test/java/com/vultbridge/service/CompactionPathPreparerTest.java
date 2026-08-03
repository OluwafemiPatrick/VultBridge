package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.vault.VaultManifest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies collision-safe compaction path preparation without writing vault records. */
class CompactionPathPreparerTest {
  private static final Instant TIMESTAMP = Instant.parse("2026-08-03T12:00:00Z");
  private static final String TEMPORARY_CANDIDATE_PREFIX = ".vultbridge-compaction-";

  @TempDir Path temporaryDirectory;

  @Test
  void choosesTheExactTimestampedFinalPathAndOwnedCandidate() throws Exception {
    Path source = temporaryDirectory.resolve("MyVault.vltb");
    var snapshot = new VaultSnapshot("MyVault.vltb", new VaultManifest(List.of()), 282);
    var operation = CompactionOperation.initial(source, temporaryDirectory, snapshot);

    try (var prepared = CompactionPathPreparer.prepare(operation, TIMESTAMP, () -> 0xa7f3c2)) {
      assertEquals(
          temporaryDirectory
              .resolve("MyVault-20260803T120000Z-a7f3c2.vltb")
              .toAbsolutePath()
              .normalize(),
          prepared.operation().finalOutputPath().orElseThrow());
      assertEquals(
          prepared.candidate().temporaryPath(), prepared.operation().candidatePath().orElseThrow());
      assertTrue(Files.exists(prepared.candidate().temporaryPath()));
    }
    assertNoTemporaryCandidates();
  }

  @Test
  void retriesAFinalNameCollisionWithoutOpeningOrReplacingIt() throws Exception {
    Path source = temporaryDirectory.resolve("MyVault.vltb");
    var snapshot = new VaultSnapshot("MyVault.vltb", new VaultManifest(List.of()), 282);
    var operation = CompactionOperation.initial(source, temporaryDirectory, snapshot);
    Path collision = temporaryDirectory.resolve("MyVault-20260803T120000Z-a7f3c2.vltb");
    Files.write(collision, new byte[] {9});
    var suffixes = new AtomicInteger();

    try (var prepared =
        CompactionPathPreparer.prepare(
            operation, TIMESTAMP, () -> suffixes.getAndIncrement() == 0 ? 0xa7f3c2 : 0x010203)) {
      assertEquals(
          temporaryDirectory
              .resolve("MyVault-20260803T120000Z-010203.vltb")
              .toAbsolutePath()
              .normalize(),
          prepared.operation().finalOutputPath().orElseThrow());
    }
    assertEquals(2, suffixes.get());
    assertEquals(9, Files.readAllBytes(collision)[0]);
    assertNoTemporaryCandidates();
  }

  @Test
  void rejectsAnUnavailableOrSymbolicDestinationDirectoryBeforeCandidateCreation()
      throws Exception {
    Path file = temporaryDirectory.resolve("not-a-directory");
    Files.write(file, new byte[] {1});
    var operation =
        CompactionOperation.initial(
            temporaryDirectory.resolve("MyVault.vltb"),
            file,
            new VaultSnapshot("MyVault.vltb", new VaultManifest(List.of()), 282));
    assertThrows(
        java.io.IOException.class,
        () -> CompactionPathPreparer.prepare(operation, TIMESTAMP, () -> 1));

    Path symbolic = temporaryDirectory.resolve("symbolic-directory");
    Files.createSymbolicLink(symbolic, temporaryDirectory.getFileName());
    var symbolicOperation =
        CompactionOperation.initial(
            temporaryDirectory.resolve("OtherVault.vltb"),
            symbolic,
            new VaultSnapshot("OtherVault.vltb", new VaultManifest(List.of()), 282));
    assertThrows(
        java.io.IOException.class,
        () -> CompactionPathPreparer.prepare(symbolicOperation, TIMESTAMP, () -> 1));
    assertNoTemporaryCandidates();
  }

  @Test
  void neverUsesASymbolicFinalPathAsTheCompactionOutput() throws Exception {
    Path source = temporaryDirectory.resolve("MyVault.vltb");
    var operation =
        CompactionOperation.initial(
            source,
            temporaryDirectory,
            new VaultSnapshot("MyVault.vltb", new VaultManifest(List.of()), 282));
    Path symbolicFinal = temporaryDirectory.resolve("MyVault-20260803T120000Z-000001.vltb");
    Files.createSymbolicLink(symbolicFinal, temporaryDirectory.resolve("missing-target"));

    assertThrows(
        java.io.IOException.class,
        () -> CompactionPathPreparer.prepare(operation, TIMESTAMP, () -> 1));
    assertTrue(Files.isSymbolicLink(symbolicFinal));
    assertNoTemporaryCandidates();
  }

  @Test
  void rejectsAConfirmedNameThatWasNotGeneratedForTheCurrentSource() throws Exception {
    Path source = temporaryDirectory.resolve("MyVault.vltb");
    var operation =
        CompactionOperation.initial(
            source,
            temporaryDirectory,
            new VaultSnapshot("MyVault.vltb", new VaultManifest(List.of()), 282));

    assertThrows(
        java.io.IOException.class,
        () -> CompactionPathPreparer.prepare(operation, "arbitrary.vltb"));
    assertNoTemporaryCandidates();
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
}
