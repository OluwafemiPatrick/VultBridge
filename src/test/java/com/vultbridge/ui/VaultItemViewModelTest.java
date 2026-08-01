package com.vultbridge.ui;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class VaultItemViewModelTest {
  @Test
  void rejectsBlankDisplayName() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new VaultItemViewModel(UUID.randomUUID(), "  ", 0, Instant.EPOCH));
  }

  @Test
  void rejectsNegativeLogicalSize() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new VaultItemViewModel(UUID.randomUUID(), "file.txt", -1, Instant.EPOCH));
  }
}
