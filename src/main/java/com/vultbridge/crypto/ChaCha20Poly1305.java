package com.vultbridge.crypto;

import com.vultbridge.vault.VaultFormat;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides the v1 ChaCha20-Poly1305 authenticated-encryption boundary through the JDK crypto API.
 *
 * <p>The caller owns the key, nonce, associated data, and plaintext inputs. Encryption returns
 * ciphertext followed by its 16-byte tag. Decryption returns owned sensitive bytes only after the
 * provider authenticates the complete input; no unauthenticated plaintext is released.
 */
public final class ChaCha20Poly1305 {
  private static final String TRANSFORMATION = "ChaCha20-Poly1305";
  private static final String KEY_ALGORITHM = "ChaCha20";

  private ChaCha20Poly1305() {}

  /** Encrypts plaintext and appends its authentication tag. */
  public static byte[] encrypt(
      SensitiveBytes key, byte[] nonce, byte[] plaintext, byte[] associatedData) {
    validateInputs(key, nonce, plaintext, associatedData);
    return process(Cipher.ENCRYPT_MODE, key, nonce, plaintext, associatedData);
  }

  /**
   * Authenticates and decrypts ciphertext into a newly owned sensitive buffer.
   *
   * @throws AuthenticationFailedException when authentication fails for any input reason
   */
  public static SensitiveBytes decrypt(
      SensitiveBytes key, byte[] nonce, byte[] ciphertext, byte[] associatedData)
      throws AuthenticationFailedException {
    validateInputs(key, nonce, ciphertext, associatedData);
    if (ciphertext.length < VaultFormat.AEAD_TAG_BYTES) {
      throw new AuthenticationFailedException();
    }

    byte[] plaintext;
    try {
      plaintext = process(Cipher.DECRYPT_MODE, key, nonce, ciphertext, associatedData);
    } catch (AuthenticationFailure failure) {
      throw new AuthenticationFailedException();
    }
    try {
      return SensitiveBytes.copyOf(plaintext);
    } finally {
      Arrays.fill(plaintext, (byte) 0);
    }
  }

  private static byte[] process(
      int mode, SensitiveBytes key, byte[] nonce, byte[] input, byte[] associatedData) {
    try {
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(mode, new SecretKeySpec(key.borrow(), KEY_ALGORITHM), new IvParameterSpec(nonce));
      cipher.updateAAD(associatedData);
      return cipher.doFinal(input);
    } catch (AEADBadTagException exception) {
      throw new AuthenticationFailure(exception);
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException(
          "Required ChaCha20-Poly1305 implementation is unavailable", exception);
    }
  }

  private static void validateInputs(
      SensitiveBytes key, byte[] nonce, byte[] input, byte[] associatedData) {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(nonce, "nonce");
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(associatedData, "associatedData");
    if (key.length() != VaultFormat.AEAD_KEY_BYTES) {
      throw new IllegalArgumentException("AEAD key must be exactly 32 bytes");
    }
    if (nonce.length != VaultFormat.AEAD_NONCE_BYTES) {
      throw new IllegalArgumentException("AEAD nonce must be exactly 12 bytes");
    }
  }

  /** Internal unchecked bridge used to keep provider causes out of the public failure contract. */
  private static final class AuthenticationFailure extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private AuthenticationFailure(AEADBadTagException cause) {
      super(cause);
    }
  }
}
