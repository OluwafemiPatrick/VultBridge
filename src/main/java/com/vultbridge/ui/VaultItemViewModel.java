package com.vultbridge.ui;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Immutable file metadata safe for presentation by the UI. */
public record VaultItemViewModel(
    UUID itemId, String displayName, long logicalSizeBytes, Instant importedAtUtc) {
  public VaultItemViewModel {
    Objects.requireNonNull(itemId, "itemId");
    Objects.requireNonNull(displayName, "displayName");
    Objects.requireNonNull(importedAtUtc, "importedAtUtc");
    if (displayName.isBlank()) {
      throw new IllegalArgumentException("Display name must not be blank");
    }
    if (logicalSizeBytes < 0) {
      throw new IllegalArgumentException("Logical size must not be negative");
    }
  }
}
