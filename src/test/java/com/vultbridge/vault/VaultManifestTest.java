package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.text.Normalizer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Verifies representation-independent MANIFEST entry and aggregate invariants. */
class VaultManifestTest {
  @Test
  void acceptsValidCaseSensitiveUniqueFlatEntries() {
    var manifest = new VaultManifest(List.of(entry("File.txt", 1, 1), entry("file.txt", 2, 2)));

    assertEquals(2, manifest.fileCount());
    assertEquals(3, manifest.liveLogicalFileBytes());
    assertThrows(UnsupportedOperationException.class, () -> manifest.entries().clear());
  }

  @Test
  void rejectsInvalidPathsControlsAndNonNfcNames() {
    for (String invalid :
        List.of("", ".", "..", "folder/file", "folder\\file", "line\nbreak", "nul\0name")) {
      assertThrows(IllegalArgumentException.class, () -> entry(invalid, 1, 1));
    }
    String decomposed = Normalizer.normalize("é", Normalizer.Form.NFD);
    assertThrows(IllegalArgumentException.class, () -> entry(decomposed, 1, 1));
    assertThrows(IllegalArgumentException.class, () -> entry("a".repeat(1025), 1, 1));
    assertThrows(IllegalArgumentException.class, () -> entry("bad-\uD800", 1, 1));
    assertThrows(IllegalArgumentException.class, () -> entry("bad-\uDC00", 1, 1));
    assertEquals("valid-😀", entry("valid-😀", 1, 1).displayName());
  }

  @Test
  void rejectsNonFileReferencesAndInconsistentLayouts() {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(1);
    var wrongRole =
        new RecordRef(
            id(1), VaultFormat.FIXED_HEADER_BYTES, layout.storedLength(), RecordRole.COMMIT);
    var wrongLength =
        new RecordRef(
            id(1), VaultFormat.FIXED_HEADER_BYTES, layout.storedLength() + 1, RecordRole.FILE);
    assertThrows(
        IllegalArgumentException.class,
        () -> new ManifestEntry("file", wrongRole, 1, 1, Instant.EPOCH));
    assertThrows(
        IllegalArgumentException.class,
        () -> new ManifestEntry("file", wrongLength, 1, 1, Instant.EPOCH));
    assertThrows(
        IllegalArgumentException.class,
        () -> new ManifestEntry("file", fileRef(1, 1), 1, 2, Instant.EPOCH));
  }

  @Test
  void rejectsDuplicateNamesAndAggregateAboveTheLiveLimit() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new VaultManifest(List.of(entry("same", 1, 1), entry("same", 1, 2))));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new VaultManifest(
                List.of(
                    entry("maximum", VaultFormat.MAXIMUM_LIVE_FILE_BYTES, 1),
                    entry("extra", 1, 2))));
  }

  @Test
  void acceptsTenThousandEntriesAndRejectsTheNext() {
    var entries = new ArrayList<ManifestEntry>(VaultFormat.MAXIMUM_FILE_COUNT + 1);
    for (int index = 0; index < VaultFormat.MAXIMUM_FILE_COUNT; index++) {
      entries.add(entry("file-" + index, 0, index + 1));
    }
    assertEquals(VaultFormat.MAXIMUM_FILE_COUNT, new VaultManifest(entries).fileCount());
    entries.add(entry("one-too-many", 0, VaultFormat.MAXIMUM_FILE_COUNT + 1));
    assertThrows(IllegalArgumentException.class, () -> new VaultManifest(entries));
  }

  private static ManifestEntry entry(String name, long size, int idValue) {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(size);
    return new ManifestEntry(
        name,
        fileRef(size, idValue),
        size,
        layout.chunkCount(),
        Instant.parse("2026-08-01T00:00:00Z"));
  }

  private static RecordRef fileRef(long size, int idValue) {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(size);
    return new RecordRef(
        id(idValue), VaultFormat.FIXED_HEADER_BYTES, layout.storedLength(), RecordRole.FILE);
  }

  private static RecordId id(int value) {
    UUID uuid = new UUID(0, value);
    var buffer = java.nio.ByteBuffer.allocate(16);
    buffer.putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits());
    return new RecordId(buffer.array());
  }
}
