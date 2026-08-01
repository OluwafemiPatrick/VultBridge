package com.vultbridge.ui;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Immutable metadata-only state for an unlocked vault view. */
public record UnlockedVaultState(
    String vaultDisplayName,
    List<VaultItemViewModel> items,
    long liveLogicalFileBytes,
    long physicalVaultBytes,
    UUID selectedItemId) {
  public static final int MAXIMUM_FILE_COUNT = 10_000;
  public static final long MAXIMUM_LIVE_FILE_BYTES = 100L * 1024 * 1024 * 1024;

  public UnlockedVaultState {
    Objects.requireNonNull(vaultDisplayName, "vaultDisplayName");
    Objects.requireNonNull(items, "items");
    if (vaultDisplayName.isBlank()) {
      throw new IllegalArgumentException("Vault display name must not be blank");
    }

    items = List.copyOf(items);
    if (items.size() > MAXIMUM_FILE_COUNT) {
      throw new IllegalArgumentException("Vault metadata exceeds the file-count limit");
    }
    if (liveLogicalFileBytes < 0 || liveLogicalFileBytes > MAXIMUM_LIVE_FILE_BYTES) {
      throw new IllegalArgumentException("Live file data is outside the supported range");
    }
    if (physicalVaultBytes < 0) {
      throw new IllegalArgumentException("Physical vault size must not be negative");
    }

    long computedLiveBytes = 0;
    var itemIds = new HashSet<UUID>();
    for (var item : items) {
      Objects.requireNonNull(item, "item");
      if (!itemIds.add(item.itemId())) {
        throw new IllegalArgumentException("Vault metadata contains a duplicate item identifier");
      }
      computedLiveBytes = Math.addExact(computedLiveBytes, item.logicalSizeBytes());
    }
    if (computedLiveBytes != liveLogicalFileBytes) {
      throw new IllegalArgumentException("Live file data does not match the item metadata");
    }
    if (selectedItemId != null && !itemIds.contains(selectedItemId)) {
      throw new IllegalArgumentException("Selected item is not present in the vault metadata");
    }
  }

  public static UnlockedVaultState empty(String vaultDisplayName, long physicalVaultBytes) {
    return new UnlockedVaultState(vaultDisplayName, List.of(), 0, physicalVaultBytes, null);
  }

  public Optional<VaultItemViewModel> selectedItem() {
    if (selectedItemId == null) {
      return Optional.empty();
    }
    return items.stream().filter(item -> item.itemId().equals(selectedItemId)).findFirst();
  }

  public boolean hasSelection() {
    return selectedItemId != null;
  }

  public boolean hasFiles() {
    return !items.isEmpty();
  }

  public UnlockedVaultState select(UUID itemId) {
    Objects.requireNonNull(itemId, "itemId");
    return new UnlockedVaultState(
        vaultDisplayName, items, liveLogicalFileBytes, physicalVaultBytes, itemId);
  }

  public UnlockedVaultState clearSelection() {
    if (selectedItemId == null) {
      return this;
    }
    return new UnlockedVaultState(
        vaultDisplayName, items, liveLogicalFileBytes, physicalVaultBytes, null);
  }
}
