package com.vultbridge.ui;

import com.vultbridge.vault.VaultFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Immutable metadata-only snapshot used to render an unlocked vault.
 *
 * <p>The constructor validates file-count and live-byte limits, unique item identifiers, aggregate
 * sizes, and selection membership. It contains no plaintext file data, passphrase, key material, or
 * complete vault path.
 */
public record UnlockedVaultState(
    String vaultDisplayName,
    List<VaultItemViewModel> items,
    long liveLogicalFileBytes,
    long physicalVaultBytes,
    UUID selectedItemId) {
  public UnlockedVaultState {
    Objects.requireNonNull(vaultDisplayName, "vaultDisplayName");
    Objects.requireNonNull(items, "items");
    if (vaultDisplayName.isBlank()) {
      throw new IllegalArgumentException("Vault display name must not be blank");
    }

    items = List.copyOf(items);
    if (items.size() > VaultFormat.MAXIMUM_FILE_COUNT) {
      throw new IllegalArgumentException("Vault metadata exceeds the file-count limit");
    }
    if (liveLogicalFileBytes < 0) {
      throw new IllegalArgumentException("Live file data must not be negative");
    }
    if (liveLogicalFileBytes > VaultFormat.MAXIMUM_LIVE_FILE_BYTES) {
      throw new IllegalArgumentException("Live file data exceeds the supported limit");
    }
    if (physicalVaultBytes < 0) {
      throw new IllegalArgumentException("Physical vault size must not be negative");
    }

    // Recompute the aggregate instead of trusting a caller-supplied total. Checked addition rejects
    // overflow before inconsistent metadata can reach the UI.
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

  /** Creates a validated empty-vault snapshot with no selected item. */
  public static UnlockedVaultState empty(String vaultDisplayName, long physicalVaultBytes) {
    return new UnlockedVaultState(vaultDisplayName, List.of(), 0, physicalVaultBytes, null);
  }

  /** Resolves the selected identifier to its item, or returns empty when nothing is selected. */
  public Optional<VaultItemViewModel> selectedItem() {
    if (selectedItemId == null) {
      return Optional.empty();
    }
    return items.stream().filter(item -> item.itemId().equals(selectedItemId)).findFirst();
  }

  /** Returns whether this snapshot contains a selected item identifier. */
  public boolean hasSelection() {
    return selectedItemId != null;
  }

  /** Returns whether the vault contains at least one live file entry. */
  public boolean hasFiles() {
    return !items.isEmpty();
  }

  /** Returns a new snapshot selecting an item that must already exist in the item list. */
  public UnlockedVaultState select(UUID itemId) {
    Objects.requireNonNull(itemId, "itemId");
    return new UnlockedVaultState(
        vaultDisplayName, items, liveLogicalFileBytes, physicalVaultBytes, itemId);
  }

  /** Returns this snapshot without a selection, reusing it when already clear. */
  public UnlockedVaultState clearSelection() {
    if (selectedItemId == null) {
      return this;
    }
    return new UnlockedVaultState(
        vaultDisplayName, items, liveLogicalFileBytes, physicalVaultBytes, null);
  }
}
