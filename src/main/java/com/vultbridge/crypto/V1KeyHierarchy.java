package com.vultbridge.crypto;

import com.vultbridge.vault.VaultEncoding;
import com.vultbridge.vault.VaultFormat;
import java.util.Arrays;
import java.util.Objects;

/**
 * Creates and unlocks the VultBridge v1 master-key hierarchy without performing filesystem I/O.
 *
 * <p>The public creation path always obtains randomness from {@link SecureRandomByteSource}; a
 * package-private injection seam supports deterministic and failure-path tests. Unlock maps every
 * authenticated-decryption failure to the same non-sensitive exception. Temporary and
 * not-yet-transferred keys are wiped on every exit, including unchecked {@link Error} paths.
 */
public final class V1KeyHierarchy {
  private static final RandomByteSource PRODUCTION_RANDOM = new SecureRandomByteSource();

  private V1KeyHierarchy() {}

  /**
   * Generates and wraps a new master key using the v1 creation parameters and production secure
   * randomness.
   *
   * @param passphrase borrowed passphrase bytes that remain owned by the caller
   * @return an envelope and newly owned live session keys that the caller must close
   */
  public static CreatedVaultKeySet create(SensitiveBytes passphrase) {
    return create(passphrase, PRODUCTION_RANDOM);
  }

  // Package-private so deterministic randomness is available to crypto tests but cannot become a
  // production caller choice.
  static CreatedVaultKeySet create(SensitiveBytes passphrase, RandomByteSource randomSource) {
    Objects.requireNonNull(passphrase, "passphrase");
    Objects.requireNonNull(randomSource, "randomSource");

    byte[] vaultId = randomBytes(randomSource, VaultFormat.VAULT_ID_BYTES);
    byte[] salt = randomBytes(randomSource, VaultFormat.KDF_SALT_BYTES);
    byte[] nonce = randomBytes(randomSource, VaultFormat.AEAD_NONCE_BYTES);
    byte[] masterKeyBytes = new byte[VaultFormat.MASTER_VAULT_KEY_BYTES];
    var parameters = Argon2idParameters.creationDefaults();

    try {
      // Allocate the sensitive destination before invoking the source so even a partially filled
      // buffer is owned by this finally block if the source throws any kind of failure.
      randomSource.nextBytes(masterKeyBytes);

      try (var masterKey = SensitiveBytes.copyOf(masterKeyBytes);
          var kek = Argon2idKdf.derive(passphrase, salt, parameters)) {
        byte[] associatedData = wrapAssociatedData(vaultId, parameters, salt, nonce);
        byte[] wrapped = ChaCha20Poly1305.encrypt(kek, nonce, masterKey.borrow(), associatedData);
        var envelope = new WrappedMasterKey(vaultId, parameters, salt, nonce, wrapped);
        return new CreatedVaultKeySet(envelope, createSessionKeys(masterKey, vaultId));
      }
    } finally {
      Arrays.fill(masterKeyBytes, (byte) 0);
    }
  }

  /** Authenticates and unwraps an existing envelope into a newly owned session key set. */
  public static VaultKeySet unlock(SensitiveBytes passphrase, WrappedMasterKey envelope)
      throws AuthenticationFailedException {
    Objects.requireNonNull(passphrase, "passphrase");
    Objects.requireNonNull(envelope, "envelope");
    byte[] vaultId = envelope.vaultId();
    byte[] salt = envelope.kdfSalt();
    byte[] nonce = envelope.wrapNonce();
    byte[] associatedData = wrapAssociatedData(vaultId, envelope.parameters(), salt, nonce);

    try (var kek = Argon2idKdf.derive(passphrase, salt, envelope.parameters());
        var masterKey =
            ChaCha20Poly1305.decrypt(kek, nonce, envelope.wrappedKey(), associatedData)) {
      return createSessionKeys(masterKey, vaultId);
    }
  }

  private static VaultKeySet createSessionKeys(SensitiveBytes masterKey, byte[] vaultId) {
    SensitiveBytes sessionMasterKey = SensitiveBytes.copyOf(masterKey.borrow());
    SensitiveBytes headerMacKey = null;
    boolean ownershipTransferred = false;
    try {
      headerMacKey = V1KeyDerivation.deriveHeaderMacKey(sessionMasterKey, vaultId);
      VaultKeySet keys = new VaultKeySet(vaultId, sessionMasterKey, headerMacKey);
      ownershipTransferred = true;
      return keys;
    } finally {
      // A finally-based handoff covers RuntimeException and Error alike. Once construction
      // succeeds, VaultKeySet exclusively owns both buffers and is responsible for closing them.
      if (!ownershipTransferred) {
        sessionMasterKey.close();
        if (headerMacKey != null) {
          headerMacKey.close();
        }
      }
    }
  }

  private static byte[] wrapAssociatedData(
      byte[] vaultId, Argon2idParameters parameters, byte[] salt, byte[] nonce) {
    byte[] prefix =
        VaultEncoding.immutableHeaderPrefix(
            vaultId,
            VaultFormat.KDF_ID_ARGON2ID,
            VaultFormat.ARGON2_VERSION_13,
            parameters.memoryKiB(),
            parameters.iterations(),
            parameters.parallelism(),
            salt,
            nonce);
    return VaultEncoding.headerWrapAssociatedData(prefix);
  }

  private static byte[] randomBytes(RandomByteSource randomSource, int length) {
    byte[] output = new byte[length];
    randomSource.nextBytes(output);
    return output;
  }
}
