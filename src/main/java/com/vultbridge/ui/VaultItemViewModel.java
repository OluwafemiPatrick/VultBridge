package com.vultbridge.ui;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable file metadata safe for presentation by the unlocked-vault table.
 *
 * <p>The model contains an opaque identifier and authenticated display metadata only; plaintext
 * file contents and cryptographic material must never be added to this UI type.
 */
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
