package com.vultbridge.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class CompactionNameGeneratorTest {
  private static final Instant TIMESTAMP = Instant.parse("2026-08-01T10:45:30Z");

  @Test
  void createsTimestampedNameFromOriginalVaultName() {
    assertEquals(
        "MyVault-20260801T104530Z-a7f3c2.vltb",
        CompactionNameGenerator.generate("MyVault.vltb", TIMESTAMP, () -> 0xa7f3c2));
  }

  @Test
  void replacesPriorCompactionSuffix() {
    assertEquals(
        "MyVault-20260801T104530Z-000001.vltb",
        CompactionNameGenerator.generate(
            "MyVault-20260731T090000Z-abcdef.vltb", TIMESTAMP, () -> 1));
  }

  @Test
  void rejectsSuffixOutsideSixHexDigits() {
    assertThrows(
        IllegalArgumentException.class,
        () -> CompactionNameGenerator.generate("MyVault", TIMESTAMP, () -> 0x0100_0000));
  }
}
