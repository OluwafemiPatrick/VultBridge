package com.vultbridge.crypto;

import com.vultbridge.vault.VaultFormat;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Derives the v1 key-encryption key with the maintained Bouncy Castle Argon2id implementation.
 *
 * <p>All public parameters, salt length, and passphrase bytes are validated before initializing the
 * memory-hard KDF. The method borrows but never closes or retains its input buffer; the caller owns
 * that lifecycle. The returned 32-byte key is independently owned and must be closed by its caller.
 */
public final class Argon2idKdf {
  private Argon2idKdf() {}

  /** Derives a 32-byte key from a validated printable-ASCII passphrase and 16-byte salt. */
  public static SensitiveBytes derive(
      SensitiveBytes passphrase, byte[] salt, Argon2idParameters parameters) {
    Objects.requireNonNull(passphrase, "passphrase");
    Objects.requireNonNull(salt, "salt");
    Objects.requireNonNull(parameters, "parameters");
    validatePassphraseBytes(passphrase.borrow());
    if (salt.length != VaultFormat.KDF_SALT_BYTES) {
      throw new IllegalArgumentException("Argon2 salt must be exactly 16 bytes");
    }

    byte[] saltCopy = Arrays.copyOf(salt, salt.length);
    byte[] derived = new byte[VaultFormat.AEAD_KEY_BYTES];
    try {
      var specification =
          new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
              .withVersion(Argon2Parameters.ARGON2_VERSION_13)
              .withMemoryAsKB(parameters.memoryKiB())
              .withIterations(parameters.iterations())
              .withParallelism(parameters.parallelism())
              .withSalt(saltCopy)
              .build();
      var generator = new Argon2BytesGenerator();
      generator.init(specification);
      generator.generateBytes(passphrase.borrow(), derived);
      return SensitiveBytes.copyOf(derived);
    } finally {
      Arrays.fill(derived, (byte) 0);
      Arrays.fill(saltCopy, (byte) 0);
    }
  }

  private static void validatePassphraseBytes(byte[] passphrase) {
    if (passphrase.length < PassphraseRules.MINIMUM_LENGTH
        || passphrase.length > PassphraseRules.MAXIMUM_LENGTH) {
      throw new IllegalArgumentException("Passphrase bytes are outside the accepted v1 length");
    }
    for (byte value : passphrase) {
      int unsigned = Byte.toUnsignedInt(value);
      if (unsigned < 0x20 || unsigned > 0x7e) {
        throw new IllegalArgumentException("Passphrase bytes are not printable ASCII");
      }
    }
  }
}
