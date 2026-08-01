package com.vultbridge.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class PassphraseRulesTest {
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
        PassphraseRules.validate("too short".toCharArray()));
  }

  @Test
  void rejectsNonAsciiPassphrase() {
    assertEquals(
        PassphraseRules.ValidationResult.INVALID_CHARACTER,
        PassphraseRules.validate("long enough café".toCharArray()));
  }
}
