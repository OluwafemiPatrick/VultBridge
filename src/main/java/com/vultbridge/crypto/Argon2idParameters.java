package com.vultbridge.crypto;

import com.vultbridge.vault.VaultFormat;

/**
 * Validated public Argon2id work factors read from or written to a VultBridge v1 header.
 *
 * <p>Construction rejects values outside the blueprint's reader bounds, ensuring untrusted header
 * values cannot trigger an excessive KDF operation. This record contains no secret material.
 */
public record Argon2idParameters(int memoryKiB, int iterations, int parallelism) {
  public Argon2idParameters {
    requireRange(
        memoryKiB,
        VaultFormat.ARGON2_MIN_MEMORY_KIB,
        VaultFormat.ARGON2_MAX_MEMORY_KIB,
        "Argon2 memory");
    requireRange(
        iterations,
        VaultFormat.ARGON2_MIN_ITERATIONS,
        VaultFormat.ARGON2_MAX_ITERATIONS,
        "Argon2 iterations");
    requireRange(
        parallelism,
        VaultFormat.ARGON2_MIN_PARALLELISM,
        VaultFormat.ARGON2_MAX_PARALLELISM,
        "Argon2 parallelism");
  }

  /** Returns the exact work factors used when creating a new v1 vault. */
  public static Argon2idParameters creationDefaults() {
    return new Argon2idParameters(
        VaultFormat.ARGON2_CREATE_MEMORY_KIB,
        VaultFormat.ARGON2_CREATE_ITERATIONS,
        VaultFormat.ARGON2_CREATE_PARALLELISM);
  }

  private static void requireRange(int value, int minimum, int maximum, String field) {
    if (value < minimum || value > maximum) {
      throw new IllegalArgumentException(field + " is outside the accepted v1 bounds");
    }
  }
}
