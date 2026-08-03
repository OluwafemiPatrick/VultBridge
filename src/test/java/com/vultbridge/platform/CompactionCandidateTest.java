package com.vultbridge.platform;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies safe candidate creation, cleanup, and non-overwriting publication. */
class CompactionCandidateTest {
  private static final String TEMPORARY_CANDIDATE_PREFIX = ".vultbridge-compaction-";

  @TempDir Path temporaryDirectory;

  @Test
  void createsPublishesAndLeavesOnlyTheFinalCandidate() throws Exception {
    Path finalPath = temporaryDirectory.resolve("compact.vltb");
    try (var candidate = CompactionCandidate.create(finalPath)) {
      assertTrue(Files.exists(candidate.temporaryPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS));
      candidate.write(channel -> channel.write(ByteBuffer.wrap(new byte[] {1, 2, 3})));
      candidate.publish();
      assertTrue(Files.exists(finalPath, java.nio.file.LinkOption.NOFOLLOW_LINKS));
    }

    assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(finalPath));
    assertNoTemporaryCandidates();
  }

  @Test
  void rejectsExistingAndSymbolicFinalPathsWithoutChangingTheExistingFile() throws Exception {
    Path existing = temporaryDirectory.resolve("existing.vltb");
    Files.write(existing, new byte[] {9});
    Path symbolic = temporaryDirectory.resolve("symbolic.vltb");
    Files.createSymbolicLink(symbolic, existing.getFileName());

    assertThrows(
        java.nio.file.FileAlreadyExistsException.class, () -> CompactionCandidate.create(existing));
    assertThrows(
        java.nio.file.FileAlreadyExistsException.class, () -> CompactionCandidate.create(symbolic));
    assertArrayEquals(new byte[] {9}, Files.readAllBytes(existing));
  }

  @Test
  void closeBeforePublicationRemovesOnlyTheOwnedCandidate() throws Exception {
    Path finalPath = temporaryDirectory.resolve("cancelled.vltb");
    try (var candidate = CompactionCandidate.create(finalPath)) {
      candidate.write(channel -> channel.write(ByteBuffer.wrap(new byte[] {1})));
    }

    assertFalse(Files.exists(finalPath));
    assertNoTemporaryCandidates();
  }

  @Test
  void destinationRaceDoesNotOverwriteTheRaceWinner() throws Exception {
    Path finalPath = temporaryDirectory.resolve("raced.vltb");
    try (var candidate = CompactionCandidate.create(finalPath)) {
      candidate.write(channel -> channel.write(ByteBuffer.wrap(new byte[] {1, 2, 3})));
      Files.write(finalPath, new byte[] {9});

      assertThrows(java.nio.file.FileAlreadyExistsException.class, candidate::publish);
    }

    assertArrayEquals(new byte[] {9}, Files.readAllBytes(finalPath));
    assertNoTemporaryCandidates();
  }

  @Test
  void directoryRenameStillCleansAnUnpublishedCandidateByIdentity() throws Exception {
    Path originalDirectory = temporaryDirectory.resolve("original");
    Path renamedDirectory = temporaryDirectory.resolve("renamed");
    Files.createDirectory(originalDirectory);
    Path finalPath = originalDirectory.resolve("compact.vltb");

    try (var candidate = CompactionCandidate.create(finalPath)) {
      candidate.write(channel -> channel.write(ByteBuffer.wrap(new byte[] {1, 2, 3})));
      Files.move(originalDirectory, renamedDirectory);
    }

    try (var paths = Files.list(renamedDirectory)) {
      assertTrue(
          paths.noneMatch(
              path -> {
                Path fileName = path.getFileName();
                return fileName != null
                    && fileName.toString().startsWith(TEMPORARY_CANDIDATE_PREFIX);
              }));
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
}
