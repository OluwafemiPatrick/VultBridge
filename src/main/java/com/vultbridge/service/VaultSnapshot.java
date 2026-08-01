package com.vultbridge.service;

import com.vultbridge.vault.VaultManifest;
import java.util.Objects;

/**
 * Represents authenticated metadata and physical size after a completed vault operation.
 *
 * <p>The snapshot contains no vault path, source path, key, passphrase, manifest plaintext bytes,
 * or file content. It is safe to map into the UI only after its producing operation has completed
 * successfully.
 */
public record VaultSnapshot(
    String vaultDisplayName, VaultManifest manifest, long physicalVaultBytes) {
  public VaultSnapshot {
    Objects.requireNonNull(vaultDisplayName, "vaultDisplayName");
    Objects.requireNonNull(manifest, "manifest");
    if (vaultDisplayName.isBlank()) {
      throw new IllegalArgumentException("Vault display name must not be blank");
    }
    if (physicalVaultBytes < 0) {
      throw new IllegalArgumentException("Physical vault size must not be negative");
    }
  }
}
