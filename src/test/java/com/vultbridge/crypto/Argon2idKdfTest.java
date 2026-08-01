package com.vultbridge.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.vault.VaultFormat;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** Verifies Argon2id bounds, input ownership, and deterministic v1 key derivation. */
class Argon2idKdfTest {
  private static final byte[] SALT = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");

  @Test
  void creationParametersMatchTheBlueprint() {
    var parameters = Argon2idParameters.creationDefaults();

    assertEquals(65_536, parameters.memoryKiB());
    assertEquals(3, parameters.iterations());
    assertEquals(1, parameters.parallelism());
  }

  @Test
  void acceptsExactReaderParameterBounds() {
    var minimum =
        new Argon2idParameters(
            VaultFormat.ARGON2_MIN_MEMORY_KIB,
            VaultFormat.ARGON2_MIN_ITERATIONS,
            VaultFormat.ARGON2_MIN_PARALLELISM);
    var maximum =
        new Argon2idParameters(
            VaultFormat.ARGON2_MAX_MEMORY_KIB,
            VaultFormat.ARGON2_MAX_ITERATIONS,
            VaultFormat.ARGON2_MAX_PARALLELISM);

    assertEquals(VaultFormat.ARGON2_MIN_MEMORY_KIB, minimum.memoryKiB());
    assertEquals(VaultFormat.ARGON2_MAX_MEMORY_KIB, maximum.memoryKiB());
  }

  @Test
  void rejectsEveryParameterImmediatelyOutsideReaderBounds() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Argon2idParameters(VaultFormat.ARGON2_MIN_MEMORY_KIB - 1, 1, 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Argon2idParameters(VaultFormat.ARGON2_MAX_MEMORY_KIB + 1, 1, 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Argon2idParameters(65_536, VaultFormat.ARGON2_MIN_ITERATIONS - 1, 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Argon2idParameters(65_536, VaultFormat.ARGON2_MAX_ITERATIONS + 1, 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Argon2idParameters(65_536, 3, VaultFormat.ARGON2_MIN_PARALLELISM - 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Argon2idParameters(65_536, 3, VaultFormat.ARGON2_MAX_PARALLELISM + 1));
  }

  @Test
  void matchesFixedV1KnownAnswerWithoutClosingInput() {
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray());
        var derived = Argon2idKdf.derive(passphrase, SALT, Argon2idParameters.creationDefaults())) {
      assertArrayEquals(
          HexFormat.of()
              .parseHex("0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e"),
          derived.copy());
      assertEquals("correct horse battery staple".length(), passphrase.length());
    }
  }

  @Test
  void rejectsInvalidSaltAndPassphraseBeforeKdfWork() {
    try (var valid =
            SensitiveBytes.copyOf("12345678".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        var shortPassphrase =
            SensitiveBytes.copyOf("1234567".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        var nonAscii =
            SensitiveBytes.copyOf(new byte[] {'1', '2', '3', '4', '5', '6', '7', (byte) 0xff})) {
      assertThrows(
          IllegalArgumentException.class,
          () -> Argon2idKdf.derive(valid, new byte[15], Argon2idParameters.creationDefaults()));
      assertThrows(
          IllegalArgumentException.class,
          () -> Argon2idKdf.derive(shortPassphrase, SALT, Argon2idParameters.creationDefaults()));
      assertThrows(
          IllegalArgumentException.class,
          () -> Argon2idKdf.derive(nonAscii, SALT, Argon2idParameters.creationDefaults()));
    }
  }
}
