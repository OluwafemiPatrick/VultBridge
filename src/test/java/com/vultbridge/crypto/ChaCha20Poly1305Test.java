package com.vultbridge.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Verifies the AEAD boundary with the RFC 8439 vector and comprehensive authentication failures.
 */
class ChaCha20Poly1305Test {
  private static final HexFormat HEX = HexFormat.of();
  private static final byte[] KEY =
      HEX.parseHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  private static final byte[] NONCE = HEX.parseHex("070000004041424344454647");
  private static final byte[] AAD = HEX.parseHex("50515253c0c1c2c3c4c5c6c7");
  private static final byte[] PLAINTEXT =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
          .getBytes(StandardCharsets.US_ASCII);
  private static final byte[] CIPHERTEXT_AND_TAG =
      HEX.parseHex(
          "d31a8d34648e60db7b86afbc53ef7ec2"
              + "a4aded51296e08fea9e2b5a736ee62d6"
              + "3dbea45e8ca9671282fafb69da92728b"
              + "1a71de0a9e060b2905d6a5b67ecd3b36"
              + "92ddbd7f2d778b8c9803aee328091b58"
              + "fab324e4fad675945585808b4831d7bc"
              + "3ff4def08e4b7a9de576d26586cec64b"
              + "6116"
              + "1ae10b594f09e26a7e902ecbd0600691");

  @Test
  void encryptionAndDecryptionMatchRfc8439() throws AuthenticationFailedException {
    try (var key = SensitiveBytes.copyOf(KEY)) {
      assertArrayEquals(CIPHERTEXT_AND_TAG, ChaCha20Poly1305.encrypt(key, NONCE, PLAINTEXT, AAD));
      try (var decrypted = ChaCha20Poly1305.decrypt(key, NONCE, CIPHERTEXT_AND_TAG, AAD)) {
        assertArrayEquals(PLAINTEXT, decrypted.copy());
      }
    }
  }

  @Test
  void supportsAuthenticatedEmptyPlaintext() throws AuthenticationFailedException {
    try (var key = SensitiveBytes.copyOf(KEY)) {
      byte[] encrypted = ChaCha20Poly1305.encrypt(key, NONCE, new byte[0], AAD);
      assertEquals(16, encrypted.length);
      try (var decrypted = ChaCha20Poly1305.decrypt(key, NONCE, encrypted, AAD)) {
        assertEquals(0, decrypted.length());
      }
    }
  }

  @Test
  void rejectsEveryTagByteMutation() {
    int tagStart = CIPHERTEXT_AND_TAG.length - 16;
    try (var key = SensitiveBytes.copyOf(KEY)) {
      for (int index = tagStart; index < CIPHERTEXT_AND_TAG.length; index++) {
        byte[] changed = Arrays.copyOf(CIPHERTEXT_AND_TAG, CIPHERTEXT_AND_TAG.length);
        changed[index] ^= 1;
        assertThrows(
            AuthenticationFailedException.class,
            () -> ChaCha20Poly1305.decrypt(key, NONCE, changed, AAD));
      }
    }
  }

  @Test
  void rejectsWrongKeyNonceAadCiphertextTruncationAndExtension() {
    byte[] wrongKey = Arrays.copyOf(KEY, KEY.length);
    wrongKey[0] ^= 1;
    byte[] wrongNonce = Arrays.copyOf(NONCE, NONCE.length);
    wrongNonce[0] ^= 1;
    byte[] wrongAad = Arrays.copyOf(AAD, AAD.length);
    wrongAad[0] ^= 1;
    byte[] changedCiphertext = Arrays.copyOf(CIPHERTEXT_AND_TAG, CIPHERTEXT_AND_TAG.length);
    changedCiphertext[0] ^= 1;
    byte[] truncated = Arrays.copyOf(CIPHERTEXT_AND_TAG, CIPHERTEXT_AND_TAG.length - 1);
    byte[] extended = Arrays.copyOf(CIPHERTEXT_AND_TAG, CIPHERTEXT_AND_TAG.length + 1);

    try (var key = SensitiveBytes.copyOf(KEY);
        var changedKey = SensitiveBytes.copyOf(wrongKey)) {
      assertAuthenticationFailure(changedKey, NONCE, CIPHERTEXT_AND_TAG, AAD);
      assertAuthenticationFailure(key, wrongNonce, CIPHERTEXT_AND_TAG, AAD);
      assertAuthenticationFailure(key, NONCE, CIPHERTEXT_AND_TAG, wrongAad);
      assertAuthenticationFailure(key, NONCE, changedCiphertext, AAD);
      assertAuthenticationFailure(key, NONCE, truncated, AAD);
      assertAuthenticationFailure(key, NONCE, extended, AAD);
      assertAuthenticationFailure(key, NONCE, new byte[15], AAD);
    }
  }

  @Test
  void rejectsInvalidKeyAndNonceLengthsBeforeProviderWork() {
    try (var shortKey = SensitiveBytes.copyOf(new byte[31]);
        var key = SensitiveBytes.copyOf(KEY)) {
      assertThrows(
          IllegalArgumentException.class,
          () -> ChaCha20Poly1305.encrypt(shortKey, NONCE, PLAINTEXT, AAD));
      assertThrows(
          IllegalArgumentException.class,
          () -> ChaCha20Poly1305.encrypt(key, new byte[11], PLAINTEXT, AAD));
    }
  }

  private static void assertAuthenticationFailure(
      SensitiveBytes key, byte[] nonce, byte[] ciphertext, byte[] aad) {
    assertThrows(
        AuthenticationFailedException.class,
        () -> ChaCha20Poly1305.decrypt(key, nonce, ciphertext, aad));
  }
}
