package com.vultbridge.platform;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies no-follow source policy and mutation-comparison metadata. */
class SourceFileInspectorTest {
  @TempDir Path temporaryDirectory;

  @Test
  void acceptsAReadableRegularFileWithoutRetainingItsPath() throws Exception {
    Path source = temporaryDirectory.resolve("source.bin");
    Files.write(source, new byte[] {1, 2, 3});

    SourceFileSnapshot snapshot = SourceFileInspector.inspect(source);

    assertEquals(3, snapshot.size());
    assertEquals(Files.getLastModifiedTime(source).toInstant(), snapshot.modifiedTime());
  }

  @Test
  void rejectsDirectoryAndSymbolicLink() throws Exception {
    Path target = temporaryDirectory.resolve("target.bin");
    Files.write(target, new byte[] {1});
    Path link = temporaryDirectory.resolve("link.bin");
    Files.createSymbolicLink(link, target.getFileName());

    assertThrows(
        SourceFileRejectedException.class, () -> SourceFileInspector.inspect(temporaryDirectory));
    assertThrows(SourceFileRejectedException.class, () -> SourceFileInspector.inspect(link));
  }

  @Test
  void comparisonDetectsSizeTimeAndAvailableIdentityChanges() {
    Instant time = Instant.ofEpochMilli(100);
    var original = new SourceFileSnapshot(3, time, "identity-a");

    assertTrue(original.matches(new SourceFileSnapshot(3, time, "identity-a")));
    assertFalse(original.matches(new SourceFileSnapshot(4, time, "identity-a")));
    assertFalse(
        original.matches(new SourceFileSnapshot(3, Instant.ofEpochMilli(101), "identity-a")));
    assertFalse(original.matches(new SourceFileSnapshot(3, time, "identity-b")));
    assertFalse(original.matches(new SourceFileSnapshot(3, time, null)));
    assertTrue(
        new SourceFileSnapshot(3, time, null).matches(new SourceFileSnapshot(3, time, null)));
  }

  @Test
  void rejectsUnreadableRegularFile() throws Exception {
    Path source = temporaryDirectory.resolve("unreadable.bin");
    Files.write(source, new byte[] {1});
    var original = Files.getPosixFilePermissions(source);
    try {
      Files.setPosixFilePermissions(source, java.util.Set.of());
      assertThrows(SourceFileRejectedException.class, () -> SourceFileInspector.inspect(source));
    } finally {
      Files.setPosixFilePermissions(source, original);
    }
  }
}
