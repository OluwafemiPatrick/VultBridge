package com.vultbridge.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.vultbridge.vault.FileRecordLayout;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.RecordId;
import com.vultbridge.vault.RecordRef;
import com.vultbridge.vault.RecordRole;
import com.vultbridge.vault.VaultFormat;
import com.vultbridge.vault.VaultManifest;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies authenticated manifest mapping into path-free UI metadata. */
class UnlockedVaultMappingTest {
  @Test
  void mapsNamesSizesTimesTotalsAndPhysicalSizeWithoutSelection() {
    var manifest = new VaultManifest(List.of(entry("first.bin", 3, 1), entry("second.bin", 4, 2)));

    var state = UnlockedVaultState.fromManifest("mapped.vltb", manifest, 999);

    assertEquals("mapped.vltb", state.vaultDisplayName());
    assertEquals(2, state.items().size());
    assertEquals("first.bin", state.items().getFirst().displayName());
    assertEquals(7, state.liveLogicalFileBytes());
    assertEquals(999, state.physicalVaultBytes());
    assertFalse(state.hasSelection());
  }

  @Test
  void repeatedFileReferenceStillReceivesDistinctOpaqueUiIdentifiers() {
    ManifestEntry first = entry("first.bin", 0, 1);
    ManifestEntry second =
        new ManifestEntry(
            "second.bin", first.fileRef(), 0, first.chunkCount(), Instant.ofEpochMilli(2));

    var state =
        UnlockedVaultState.fromManifest(
            "duplicates.vltb", new VaultManifest(List.of(first, second)), 1);

    assertNotEquals(state.items().get(0).itemId(), state.items().get(1).itemId());
  }

  private static ManifestEntry entry(String name, long size, int marker) {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(size);
    byte[] id = new byte[VaultFormat.RECORD_ID_BYTES];
    id[id.length - 1] = (byte) marker;
    return new ManifestEntry(
        name,
        new RecordRef(new RecordId(id), 282, layout.storedLength(), RecordRole.FILE),
        size,
        layout.chunkCount(),
        Instant.ofEpochMilli(marker));
  }
}
