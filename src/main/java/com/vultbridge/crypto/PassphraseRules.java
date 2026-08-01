package com.vultbridge.crypto;

/**
 * Validates passphrases against the length and character rules accepted by vault format v1.
 *
 * <p>The API accepts a mutable character array so callers can overwrite their temporary copy after
 * validation instead of retaining an immutable {@link String} longer than necessary.
 */
public final class PassphraseRules {
  public static final int MINIMUM_LENGTH = 8;
  public static final int MAXIMUM_LENGTH = 64;

  private PassphraseRules() {}

  /** Returns the authoritative user-facing description of the accepted v1 passphrase range. */
  public static String requirementDescription() {
    return MINIMUM_LENGTH + "–" + MAXIMUM_LENGTH + " printable ASCII characters";
  }

  /** Classifies a passphrase without storing or transforming its contents. */
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

  /** Non-sensitive result categories suitable for choosing user-facing validation text. */
  public enum ValidationResult {
    VALID,
    INVALID_LENGTH,
    INVALID_CHARACTER
  }
}
