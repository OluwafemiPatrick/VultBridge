package com.vultbridge.crypto;

import java.util.Objects;

/**
 * Converts a validated v1 passphrase to its exact one-byte-per-character ASCII representation.
 *
 * <p>The caller retains ownership of the input {@code char[]} and must wipe it. The returned
 * sensitive buffer owns its encoded bytes and must be closed. Invalid input is rejected before an
 * output buffer is created.
 */
public final class PassphraseEncoding {
  private PassphraseEncoding() {}

  /** Validates and encodes a caller-owned passphrase without retaining the input array. */
  public static SensitiveBytes encode(char[] passphrase) {
    Objects.requireNonNull(passphrase, "passphrase");
    PassphraseRules.ValidationResult result = PassphraseRules.validate(passphrase);
    if (result != PassphraseRules.ValidationResult.VALID) {
      throw new IllegalArgumentException("Passphrase does not satisfy the v1 encoding rules");
    }

    byte[] encoded = new byte[passphrase.length];
    for (int index = 0; index < passphrase.length; index++) {
      // Validation proves every UTF-16 code unit is exactly one printable ASCII byte.
      encoded[index] = (byte) passphrase[index];
    }
    try {
      return SensitiveBytes.copyOf(encoded);
    } finally {
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }
}
