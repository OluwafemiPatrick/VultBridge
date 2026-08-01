package com.vultbridge.vault;

import com.vultbridge.crypto.AuthenticationFailedException;
import com.vultbridge.crypto.ChaCha20Poly1305;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.crypto.V1KeyDerivation;
import com.vultbridge.crypto.VaultKeySet;
import java.util.Objects;

/**
 * Encrypts and authenticates v1 record bodies using per-record derived keys and canonical AAD.
 *
 * <p>MANIFEST and COMMIT are bounded single-body operations with an all-zero nonce. FILE chunks are
 * handled individually against a canonical {@link FileRecordLayout}, preserving bounded-memory
 * streaming. Plaintext inputs are borrowed synchronously and never retained; decrypted plaintext is
 * returned as an owned {@link SensitiveBytes} that callers must close.
 */
public final class RecordCrypto {
  private RecordCrypto() {}

  /** Encrypts one complete MANIFEST or COMMIT plaintext body. */
  public static byte[] encryptSingleBody(
      VaultKeySet keys, RecordId recordId, RecordRole role, byte[] plaintext) {
    requireSingleBody(role, plaintext.length);
    return encrypt(keys, recordId, role, 0, plaintext, VaultEncoding.singleRecordNonce());
  }

  /** Authenticates and decrypts one complete bounded MANIFEST or COMMIT body. */
  public static SensitiveBytes decryptSingleBody(
      VaultKeySet keys, RecordId recordId, RecordRole role, byte[] encryptedBody)
      throws VaultDataException {
    Objects.requireNonNull(encryptedBody, "encryptedBody");
    int plaintextLength;
    try {
      plaintextLength = Math.subtractExact(encryptedBody.length, VaultFormat.AEAD_TAG_BYTES);
      requireSingleBody(role, plaintextLength);
    } catch (IllegalArgumentException | ArithmeticException exception) {
      throw new VaultDataException();
    }
    return decrypt(
        keys, recordId, role, 0, plaintextLength, encryptedBody, VaultEncoding.singleRecordNonce());
  }

  /** Encrypts one exact FILE chunk without retaining its caller-owned plaintext. */
  public static byte[] encryptFileChunk(
      VaultKeySet keys,
      RecordId recordId,
      FileRecordLayout layout,
      long chunkIndex,
      byte[] plaintext) {
    Objects.requireNonNull(layout, "layout");
    Objects.requireNonNull(plaintext, "plaintext");
    if (plaintext.length != layout.chunkPlaintextLength(chunkIndex)) {
      throw new IllegalArgumentException("FILE chunk plaintext length is inconsistent");
    }
    return encrypt(
        keys,
        recordId,
        RecordRole.FILE,
        chunkIndex,
        plaintext,
        VaultEncoding.fileChunkNonce(chunkIndex));
  }

  /** Authenticates and decrypts one exact FILE chunk into an owned plaintext buffer. */
  public static SensitiveBytes decryptFileChunk(
      VaultKeySet keys,
      RecordId recordId,
      FileRecordLayout layout,
      long chunkIndex,
      byte[] encryptedChunk)
      throws VaultDataException {
    Objects.requireNonNull(layout, "layout");
    Objects.requireNonNull(encryptedChunk, "encryptedChunk");
    int plaintextLength = layout.chunkPlaintextLength(chunkIndex);
    if (encryptedChunk.length != plaintextLength + VaultFormat.AEAD_TAG_BYTES) {
      throw new VaultDataException();
    }
    return decrypt(
        keys,
        recordId,
        RecordRole.FILE,
        chunkIndex,
        plaintextLength,
        encryptedChunk,
        VaultEncoding.fileChunkNonce(chunkIndex));
  }

  private static byte[] encrypt(
      VaultKeySet keys,
      RecordId recordId,
      RecordRole role,
      long chunkIndex,
      byte[] plaintext,
      byte[] nonce) {
    Objects.requireNonNull(keys, "keys");
    Objects.requireNonNull(recordId, "recordId");
    Objects.requireNonNull(role, "role");
    Objects.requireNonNull(plaintext, "plaintext");
    byte[] vaultId = keys.vaultId();
    byte[] aad =
        VaultEncoding.recordAssociatedData(
            vaultId, recordId.bytes(), role.code(), chunkIndex, plaintext.length);
    try (var masterKey = keys.copyMasterVaultKey();
        var recordKey = V1KeyDerivation.deriveRecordKey(masterKey, vaultId, recordId.bytes())) {
      return ChaCha20Poly1305.encrypt(recordKey, nonce, plaintext, aad);
    }
  }

  private static SensitiveBytes decrypt(
      VaultKeySet keys,
      RecordId recordId,
      RecordRole role,
      long chunkIndex,
      int plaintextLength,
      byte[] encryptedBody,
      byte[] nonce)
      throws VaultDataException {
    Objects.requireNonNull(keys, "keys");
    Objects.requireNonNull(recordId, "recordId");
    Objects.requireNonNull(role, "role");
    byte[] vaultId = keys.vaultId();
    byte[] aad =
        VaultEncoding.recordAssociatedData(
            vaultId, recordId.bytes(), role.code(), chunkIndex, plaintextLength);
    try (var masterKey = keys.copyMasterVaultKey();
        var recordKey = V1KeyDerivation.deriveRecordKey(masterKey, vaultId, recordId.bytes())) {
      try {
        return ChaCha20Poly1305.decrypt(recordKey, nonce, encryptedBody, aad);
      } catch (AuthenticationFailedException exception) {
        throw new VaultDataException();
      }
    }
  }

  private static void requireSingleBody(RecordRole role, int plaintextLength) {
    Objects.requireNonNull(role, "role");
    int maximum =
        switch (role) {
          case MANIFEST -> VaultFormat.MAXIMUM_MANIFEST_PLAINTEXT_BYTES;
          case COMMIT -> VaultFormat.MAXIMUM_COMMIT_PLAINTEXT_BYTES;
          case FILE -> throw new IllegalArgumentException("FILE records require chunk processing");
        };
    if (plaintextLength < 0 || plaintextLength > maximum) {
      throw new IllegalArgumentException("Record plaintext exceeds its role bound");
    }
  }
}
