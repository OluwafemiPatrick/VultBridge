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

/** Verifies create-new export publication and non-overwrite behavior. */
class ExportFileTargetTest {
  @TempDir Path temporaryDirectory;

  @Test
  void forcesAndPublishesACompletedNewDestination() throws Exception {
    Path destination = temporaryDirectory.resolve("published.bin");
    try (var target = ExportFileTarget.create(destination)) {
      target.write(channel -> channel.write(ByteBuffer.wrap(new byte[] {1, 2, 3})));
      target.publish();
    }
    assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(destination));
    assertTrue(
        Files.getPosixFilePermissions(destination)
            .equals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
  }

  @Test
  void rejectsExistingAndSymbolicDestinationsWithoutChangingThem() throws Exception {
    Path existing = temporaryDirectory.resolve("existing.bin");
    Files.write(existing, new byte[] {9});
    Path symbolic = temporaryDirectory.resolve("symbolic.bin");
    Files.createSymbolicLink(symbolic, existing.getFileName());

    assertThrows(
        java.nio.file.FileAlreadyExistsException.class, () -> ExportFileTarget.create(existing));
    assertThrows(
        java.nio.file.FileAlreadyExistsException.class, () -> ExportFileTarget.create(symbolic));
    assertArrayEquals(new byte[] {9}, Files.readAllBytes(existing));
  }

  @Test
  void closingBeforePublicationRemovesTheTemporaryOutput() throws Exception {
    Path destination = temporaryDirectory.resolve("cancelled.bin");
    try (var target = ExportFileTarget.create(destination)) {
      target.write(channel -> channel.write(ByteBuffer.wrap(new byte[] {1})));
    }
    assertFalse(Files.exists(destination));
    try (var paths = Files.list(temporaryDirectory)) {
      assertTrue(paths.noneMatch(path -> path.toString().contains(".vultbridge-export-")));
    }
  }

  @Test
  void destinationRaceDoesNotOverwriteAndCloseRemovesOwnedTemporary() throws Exception {
    Path destination = temporaryDirectory.resolve("raced.bin");
    try (var target = ExportFileTarget.create(destination)) {
      target.write(channel -> channel.write(ByteBuffer.wrap(new byte[] {1, 2, 3})));
      Files.write(destination, new byte[] {9});

      assertThrows(java.nio.file.FileAlreadyExistsException.class, target::publish);
    }

    assertArrayEquals(new byte[] {9}, Files.readAllBytes(destination));
    assertNoTemporaryFiles();
  }

  @Test
  void directoryRenameStillRemovesUnpublishedPlaintext() throws Exception {
    Path originalDirectory = temporaryDirectory.resolve("original");
    Path renamedDirectory = temporaryDirectory.resolve("renamed");
    Files.createDirectory(originalDirectory);
    Path destination = originalDirectory.resolve("output.bin");

    try (var target = ExportFileTarget.create(destination)) {
      target.write(channel -> channel.write(ByteBuffer.wrap(new byte[] {1, 2, 3})));
      Files.move(originalDirectory, renamedDirectory);

      assertThrows(java.nio.file.NoSuchFileException.class, target::publish);
    }

    try (var paths = Files.list(renamedDirectory)) {
      assertTrue(paths.noneMatch(path -> path.toString().contains(".vultbridge-export-")));
    }
  }

  private void assertNoTemporaryFiles() throws Exception {
    try (var paths = Files.list(temporaryDirectory)) {
      assertTrue(paths.noneMatch(path -> path.toString().contains(".vultbridge-export-")));
    }
  }
}
