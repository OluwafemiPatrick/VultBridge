package com.vultbridge.crypto;

import com.vultbridge.vault.VaultEncoding;
import com.vultbridge.vault.VaultFormat;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * Derives domain-separated VultBridge v1 subkeys from a master vault key using HKDF-SHA-256.
 *
 * <p>Inputs are borrowed synchronously and never retained or closed. Each returned 32-byte key has
 * independent ownership and must be closed by its caller. HKDF info bytes come exclusively from
 * {@link VaultEncoding} to prevent divergent authenticated encodings.
 */
public final class V1KeyDerivation {
  private V1KeyDerivation() {}

  /** Derives the key used to authenticate both mutable fixed-header slots. */
  public static SensitiveBytes deriveHeaderMacKey(SensitiveBytes masterVaultKey, byte[] vaultId) {
    return derive(masterVaultKey, vaultId, VaultEncoding.headerSlotKeyInfo());
  }

  /** Derives the unique AEAD key for one record identifier. */
  public static SensitiveBytes deriveRecordKey(
      SensitiveBytes masterVaultKey, byte[] vaultId, byte[] recordId) {
    return derive(masterVaultKey, vaultId, VaultEncoding.recordKeyInfo(recordId));
  }

  private static SensitiveBytes derive(SensitiveBytes masterVaultKey, byte[] vaultId, byte[] info) {
    Objects.requireNonNull(masterVaultKey, "masterVaultKey");
    Objects.requireNonNull(vaultId, "vaultId");
    if (masterVaultKey.length() != VaultFormat.MASTER_VAULT_KEY_BYTES) {
      throw new IllegalArgumentException("Master vault key must be exactly 32 bytes");
    }
    if (vaultId.length != VaultFormat.VAULT_ID_BYTES) {
      throw new IllegalArgumentException("Vault ID must be exactly 16 bytes");
    }

    byte[] saltCopy = Arrays.copyOf(vaultId, vaultId.length);
    byte[] infoCopy = Arrays.copyOf(info, info.length);
    byte[] output = new byte[VaultFormat.AEAD_KEY_BYTES];
    try {
      var generator = new HKDFBytesGenerator(new SHA256Digest());
      generator.init(new HKDFParameters(masterVaultKey.borrow(), saltCopy, infoCopy));
      generator.generateBytes(output, 0, output.length);
      return SensitiveBytes.copyOf(output);
    } finally {
      Arrays.fill(output, (byte) 0);
      Arrays.fill(saltCopy, (byte) 0);
      Arrays.fill(infoCopy, (byte) 0);
    }
  }
}
