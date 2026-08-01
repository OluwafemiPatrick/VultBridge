package com.vultbridge.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Exercises ownership, copying, and destruction guarantees for short-lived sensitive buffers. */
class SensitiveBytesTest {
  @Test
  void copiesCallerInputAndDoesNotExposeItsOwnedArray() {
    byte[] input = {1, 2, 3};
    try (var sensitive = SensitiveBytes.copyOf(input)) {
      input[0] = 9;
      byte[] firstCopy = sensitive.copy();
      firstCopy[1] = 9;

      assertArrayEquals(new byte[] {1, 2, 3}, sensitive.copy());
      Arrays.fill(firstCopy, (byte) 0);
    }
  }

  @Test
  void closeWipesOwnedBytesAndIsIdempotent() {
    var sensitive = SensitiveBytes.copyOf(new byte[] {4, 5, 6});
    byte[] borrowed = sensitive.borrow();
    assertFalse(sensitive.isDestroyed());

    sensitive.close();
    sensitive.close();

    assertTrue(sensitive.isDestroyed());
    assertArrayEquals(new byte[] {0, 0, 0}, borrowed);
    assertThrows(IllegalStateException.class, sensitive::copy);
    assertThrows(IllegalStateException.class, sensitive::length);
  }

  @Test
  void passphraseEncodingIsExactAsciiAndOwnsItsOutput() {
    char[] passphrase = "Eight123".toCharArray();
    try (var encoded = PassphraseEncoding.encode(passphrase)) {
      assertEquals(passphrase.length, encoded.length());
      assertArrayEquals(new byte[] {69, 105, 103, 104, 116, 49, 50, 51}, encoded.copy());
      assertArrayEquals("Eight123".toCharArray(), passphrase);
    } finally {
      Arrays.fill(passphrase, '\0');
    }
  }

  @Test
  void passphraseEncodingRejectsInvalidInput() {
    assertThrows(
        IllegalArgumentException.class, () -> PassphraseEncoding.encode("1234567".toCharArray()));
    assertThrows(
        IllegalArgumentException.class,
        () -> PassphraseEncoding.encode("not ascii é".toCharArray()));
    assertThrows(NullPointerException.class, () -> PassphraseEncoding.encode(null));
  }
}
