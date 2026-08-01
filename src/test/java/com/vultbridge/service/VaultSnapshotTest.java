package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.vault.VaultManifest;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies the metadata-only vault-operation result boundary. */
class VaultSnapshotTest {
  @Test
  void acceptsAuthenticatedMetadataAndNonNegativePhysicalSize() {
    var manifest = new VaultManifest(List.of());

    var snapshot = new VaultSnapshot("snapshot.vltb", manifest, 282);

    assertEquals(manifest, snapshot.manifest());
    assertEquals(282, snapshot.physicalVaultBytes());
  }

  @Test
  void rejectsNegativePhysicalSize() {
    var manifest = new VaultManifest(List.of());
    assertThrows(
        IllegalArgumentException.class, () -> new VaultSnapshot("snapshot.vltb", manifest, -1));
  }
}
