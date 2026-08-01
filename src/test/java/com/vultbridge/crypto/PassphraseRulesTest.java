package com.vultbridge.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class PassphraseRulesTest {
  @Test
  void requirementDescriptionUsesTheAuthoritativeBounds() {
    assertEquals("8–64 printable ASCII characters", PassphraseRules.requirementDescription());
  }

  @Test
  void acceptsPrintableAsciiWithinBounds() {
    assertEquals(
        PassphraseRules.ValidationResult.VALID,
        PassphraseRules.validate("correct horse battery staple".toCharArray()));
  }

  @Test
  void rejectsShortPassphrase() {
    assertEquals(
        PassphraseRules.ValidationResult.INVALID_LENGTH,
        PassphraseRules.validate("1234567".toCharArray()));
  }

  @Test
  void acceptsPassphrasesAtLengthBoundaries() {
    assertEquals(
        PassphraseRules.ValidationResult.VALID, PassphraseRules.validate("12345678".toCharArray()));
    assertEquals(
        PassphraseRules.ValidationResult.VALID,
        PassphraseRules.validate("a".repeat(64).toCharArray()));
  }

  @Test
  void rejectsPassphraseAboveMaximumLength() {
    assertEquals(
        PassphraseRules.ValidationResult.INVALID_LENGTH,
        PassphraseRules.validate("a".repeat(65).toCharArray()));
  }

  @Test
  void rejectsNonAsciiPassphrase() {
    assertEquals(
        PassphraseRules.ValidationResult.INVALID_CHARACTER,
        PassphraseRules.validate("long enough café".toCharArray()));
  }
}
