package com.vultbridge.crypto;

import com.vultbridge.vault.VaultFormat;
import java.util.Arrays;
import java.util.Objects;

/**
 * Owns the master vault key and derived header-slot MAC key for one unlocked vault session.
 *
 * <p>Callers receive independently owned copies when a key is needed and must close those copies.
 * Closing this set wipes both retained keys and is idempotent. The public vault ID is defensively
 * copied and is not secret.
 */
public final class VaultKeySet implements AutoCloseable {
  private final byte[] vaultId;
  private final SensitiveBytes masterVaultKey;
  private final SensitiveBytes headerMacKey;

  VaultKeySet(byte[] vaultId, SensitiveBytes masterVaultKey, SensitiveBytes headerMacKey) {
    Objects.requireNonNull(vaultId, "vaultId");
    if (vaultId.length != VaultFormat.VAULT_ID_BYTES) {
      throw new IllegalArgumentException("Vault ID must be exactly 16 bytes");
    }
    this.vaultId = Arrays.copyOf(vaultId, vaultId.length);
    this.masterVaultKey = Objects.requireNonNull(masterVaultKey, "masterVaultKey");
    this.headerMacKey = Objects.requireNonNull(headerMacKey, "headerMacKey");
  }

  /** Returns a copy of the non-secret vault identifier. */
  public byte[] vaultId() {
    return Arrays.copyOf(vaultId, vaultId.length);
  }

  /** Returns a new independently owned master-key copy that the caller must close. */
  public SensitiveBytes copyMasterVaultKey() {
    return SensitiveBytes.copyOf(masterVaultKey.borrow());
  }

  /** Returns a new independently owned header-MAC-key copy that the caller must close. */
  public SensitiveBytes copyHeaderMacKey() {
    return SensitiveBytes.copyOf(headerMacKey.borrow());
  }

  /** Returns whether this set has wiped its two retained keys. */
  public boolean isDestroyed() {
    return masterVaultKey.isDestroyed() && headerMacKey.isDestroyed();
  }

  @Override
  public void close() {
    masterVaultKey.close();
    headerMacKey.close();
  }
}
