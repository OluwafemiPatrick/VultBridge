package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.platform.SourceFileSnapshot;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.RecordId;
import com.vultbridge.vault.RecordRef;
import com.vultbridge.vault.RecordRole;
import com.vultbridge.vault.VaultFormat;
import com.vultbridge.vault.VaultManifest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies import name, count, and live-data preflight boundaries. */
class ImportPreflightTest {
  @Test
  void rejectsInvalidName() throws Exception {
    assertCategory(
        JobFailureCategory.INPUT_REJECTED,
        () -> ImportPreflight.validate(new VaultManifest(List.of()), "bad/name", snapshot(1)));
  }

  @Test
  void rejectsDuplicateNameAndFileCountBoundary() throws Exception {
    ManifestEntry existing = entry("duplicate.bin", 0, 1);
    assertCategory(
        JobFailureCategory.INPUT_REJECTED,
        () ->
            ImportPreflight.validate(
                new VaultManifest(List.of(existing)), "duplicate.bin", snapshot(0)));

    var full = new ArrayList<ManifestEntry>(VaultFormat.MAXIMUM_FILE_COUNT);
    for (int index = 0; index < VaultFormat.MAXIMUM_FILE_COUNT; index++) {
      full.add(entry("file-" + index, 0, index));
    }
    assertCategory(
        JobFailureCategory.INPUT_REJECTED,
        () -> ImportPreflight.validate(new VaultManifest(full), "extra.bin", snapshot(0)));
  }

  @Test
  void acceptsTheTenThousandthEntry() throws Exception {
    var almostFull = new ArrayList<ManifestEntry>(VaultFormat.MAXIMUM_FILE_COUNT - 1);
    for (int index = 0; index < VaultFormat.MAXIMUM_FILE_COUNT - 1; index++) {
      almostFull.add(entry("existing-" + index, 0, index));
    }

    var accepted =
        ImportPreflight.validate(new VaultManifest(almostFull), "ten-thousandth.bin", snapshot(0));

    assertEquals("ten-thousandth.bin", accepted.displayName());
  }

  @Test
  void acceptsExactLiveByteLimitAndRejectsOneByteBeyondIt() throws Exception {
    VaultManifest almostFull =
        new VaultManifest(List.of(entry("large.bin", VaultFormat.MAXIMUM_LIVE_FILE_BYTES - 1, 1)));

    assertEquals(
        1, ImportPreflight.validate(almostFull, "last.bin", snapshot(1)).layout().logicalSize());
    assertCategory(
        JobFailureCategory.INPUT_REJECTED,
        () -> ImportPreflight.validate(almostFull, "too-much.bin", snapshot(2)));
  }

  @Test
  void rejectsCheckedLiveByteOverflow() throws Exception {
    VaultManifest nonEmpty = new VaultManifest(List.of(entry("one-byte.bin", 1, 1)));

    assertCategory(
        JobFailureCategory.INPUT_REJECTED,
        () -> ImportPreflight.validate(nonEmpty, "overflow.bin", snapshot(Long.MAX_VALUE)));
  }

  private static ManifestEntry entry(String name, long size, int marker) {
    var layout = com.vultbridge.vault.FileRecordLayout.forLogicalSize(size);
    byte[] id = new byte[VaultFormat.RECORD_ID_BYTES];
    id[id.length - 1] = (byte) marker;
    return new ManifestEntry(
        name,
        new RecordRef(new RecordId(id), 282, layout.storedLength(), RecordRole.FILE),
        size,
        layout.chunkCount(),
        Instant.EPOCH);
  }

  private static SourceFileSnapshot snapshot(long size) {
    return new SourceFileSnapshot(size, Instant.ofEpochMilli(1), "key");
  }

  private static void assertCategory(JobFailureCategory expected, ThrowingOperation operation)
      throws Exception {
    VaultOperationException failure =
        assertThrows(VaultOperationException.class, operation::execute);
    assertEquals(expected, failure.category());
  }

  @FunctionalInterface
  private interface ThrowingOperation {
    void execute() throws Exception;
  }
}
