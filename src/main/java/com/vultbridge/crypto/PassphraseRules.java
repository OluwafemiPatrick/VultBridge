package com.vultbridge.crypto;

/** Validates the unambiguous printable-ASCII passphrases accepted by vault format v1. */
public final class PassphraseRules {
  public static final int MINIMUM_LENGTH = 9;
  public static final int MAXIMUM_LENGTH = 64;

  private PassphraseRules() {}

  public static ValidationResult validate(char[] passphrase) {
    if (passphrase.length < MINIMUM_LENGTH || passphrase.length > MAXIMUM_LENGTH) {
      return ValidationResult.INVALID_LENGTH;
    }
    for (char character : passphrase) {
      if (character < 0x20 || character > 0x7e) {
        return ValidationResult.INVALID_CHARACTER;
      }
    }
    return ValidationResult.VALID;
  }

  public enum ValidationResult {
    VALID,
    INVALID_LENGTH,
    INVALID_CHARACTER
  }
}
