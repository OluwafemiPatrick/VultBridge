package com.vultbridge.crypto;

import com.vultbridge.vault.VaultFormat;
import java.util.Arrays;
import java.util.Objects;

/**
 * Holds validated public header fields required to derive and authenticate a wrapped master key.
 *
 * <p>All arrays are defensively copied on construction and access. The wrapped value is ciphertext
 * plus its authentication tag, not plaintext key material. A class is used instead of a record so
 * mutable array identity cannot leak through generated accessors or equality methods.
 */
public final class WrappedMasterKey {
  private final byte[] vaultId;
  private final Argon2idParameters parameters;
  private final byte[] kdfSalt;
  private final byte[] wrapNonce;
  private final byte[] wrappedKey;

  /** Creates a validated defensive copy of all public wrapped-key fields. */
  public WrappedMasterKey(
      byte[] vaultId,
      Argon2idParameters parameters,
      byte[] kdfSalt,
      byte[] wrapNonce,
      byte[] wrappedKey) {
    this.vaultId = copyExact(vaultId, VaultFormat.VAULT_ID_BYTES, "vault ID");
    this.parameters = Objects.requireNonNull(parameters, "parameters");
    this.kdfSalt = copyExact(kdfSalt, VaultFormat.KDF_SALT_BYTES, "KDF salt");
    this.wrapNonce = copyExact(wrapNonce, VaultFormat.AEAD_NONCE_BYTES, "wrap nonce");
    this.wrappedKey =
        copyExact(
            wrappedKey, VaultFormat.WRAPPED_MASTER_VAULT_KEY_BYTES, "wrapped master vault key");
  }

  /** Returns a copy of the public vault identifier. */
  public byte[] vaultId() {
    return Arrays.copyOf(vaultId, vaultId.length);
  }

  /** Returns the validated public Argon2id work factors. */
  public Argon2idParameters parameters() {
    return parameters;
  }

  /** Returns a copy of the public KDF salt. */
  public byte[] kdfSalt() {
    return Arrays.copyOf(kdfSalt, kdfSalt.length);
  }

  /** Returns a copy of the public AEAD wrapping nonce. */
  public byte[] wrapNonce() {
    return Arrays.copyOf(wrapNonce, wrapNonce.length);
  }

  /** Returns a copy of the wrapped master-key ciphertext and tag. */
  public byte[] wrappedKey() {
    return Arrays.copyOf(wrappedKey, wrappedKey.length);
  }

  private static byte[] copyExact(byte[] value, int expectedLength, String field) {
    Objects.requireNonNull(value, field);
    if (value.length != expectedLength) {
      throw new IllegalArgumentException(field + " has an invalid length");
    }
    return Arrays.copyOf(value, value.length);
  }
}
