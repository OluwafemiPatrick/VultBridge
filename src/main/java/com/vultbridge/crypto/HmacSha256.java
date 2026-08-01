package com.vultbridge.crypto;

import com.vultbridge.vault.VaultFormat;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Computes and verifies v1 HMAC-SHA-256 values using the JDK cryptographic provider interface.
 *
 * <p>The key is borrowed only for the synchronous operation and is never retained or closed. MAC
 * verification uses a constant-time comparison and rejects tags of the wrong length before provider
 * work.
 */
public final class HmacSha256 {
  private static final String ALGORITHM = "HmacSHA256";

  private HmacSha256() {}

  /** Computes a 32-byte HMAC for caller-owned, non-secret authenticated input. */
  public static byte[] authenticate(SensitiveBytes key, byte[] input) {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(input, "input");
    if (key.length() != VaultFormat.HMAC_SHA256_BYTES) {
      throw new IllegalArgumentException("HMAC key must be exactly 32 bytes");
    }
    try {
      Mac mac = Mac.getInstance(ALGORITHM);
      mac.init(new SecretKeySpec(key.borrow(), ALGORITHM));
      return mac.doFinal(input);
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException(
          "Required HMAC-SHA-256 implementation is unavailable", exception);
    }
  }

  /** Verifies an expected 32-byte HMAC without data-dependent early exit. */
  public static boolean verify(SensitiveBytes key, byte[] input, byte[] expectedTag) {
    Objects.requireNonNull(expectedTag, "expectedTag");
    if (expectedTag.length != VaultFormat.HMAC_SHA256_BYTES) {
      return false;
    }
    return MessageDigest.isEqual(authenticate(key, input), expectedTag);
  }
}
