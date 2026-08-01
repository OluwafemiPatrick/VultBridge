package com.vultbridge.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.vault.VaultFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UnlockedVaultStateTest {
  private static final UUID ITEM_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
  private static final VaultItemViewModel ITEM =
      new VaultItemViewModel(ITEM_ID, "document.pdf", 100, Instant.EPOCH);

  @Test
  void defensivelyCopiesItemMetadata() {
    var mutableItems = new java.util.ArrayList<>(List.of(ITEM));
    var state = new UnlockedVaultState("MyVault", mutableItems, 100, 256, null);

    mutableItems.clear();

    assertEquals(1, state.items().size());
    assertThrows(UnsupportedOperationException.class, () -> state.items().clear());
  }

  @Test
  void selectsOnlyAnExistingItem() {
    var state = new UnlockedVaultState("MyVault", List.of(ITEM), 100, 256, null);

    var selected = state.select(ITEM_ID);

    assertTrue(selected.hasSelection());
    assertEquals(ITEM, selected.selectedItem().orElseThrow());
    assertFalse(selected.clearSelection().hasSelection());
    assertThrows(IllegalArgumentException.class, () -> selectForTest(state, UUID.randomUUID()));
  }

  @Test
  void rejectsMismatchedLiveByteTotal() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new UnlockedVaultState("MyVault", List.of(ITEM), 99, 256, null));
  }

  @Test
  void rejectsDuplicateItemIdentifiers() {
    var duplicate = new VaultItemViewModel(ITEM_ID, "other.pdf", 20, Instant.EPOCH);

    assertThrows(
        IllegalArgumentException.class,
        () -> new UnlockedVaultState("MyVault", List.of(ITEM, duplicate), 120, 256, null));
  }

  @Test
  void emptyVaultHasNoFilesOrSelection() {
    var state = UnlockedVaultState.empty("MyVault", 256);

    assertFalse(state.hasFiles());
    assertFalse(state.hasSelection());
    assertTrue(state.selectedItem().isEmpty());
  }

  @Test
  void acceptsAndRejectsTheAuthoritativeLiveDataBoundary() {
    var maximumItem =
        new VaultItemViewModel(
            ITEM_ID, "maximum.bin", VaultFormat.MAXIMUM_LIVE_FILE_BYTES, Instant.EPOCH);

    var accepted =
        new UnlockedVaultState(
            "MyVault",
            List.of(maximumItem),
            VaultFormat.MAXIMUM_LIVE_FILE_BYTES,
            VaultFormat.MAXIMUM_LIVE_FILE_BYTES,
            null);

    assertEquals(VaultFormat.MAXIMUM_LIVE_FILE_BYTES, accepted.liveLogicalFileBytes());
    var oversizedItem =
        new VaultItemViewModel(
            ITEM_ID, "oversized.bin", VaultFormat.MAXIMUM_LIVE_FILE_BYTES + 1, Instant.EPOCH);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new UnlockedVaultState(
                "MyVault",
                List.of(oversizedItem),
                VaultFormat.MAXIMUM_LIVE_FILE_BYTES + 1,
                VaultFormat.MAXIMUM_LIVE_FILE_BYTES + 1,
                null));
  }

  @Test
  void acceptsAndRejectsTheAuthoritativeFileCountBoundary() {
    var items = new ArrayList<VaultItemViewModel>(VaultFormat.MAXIMUM_FILE_COUNT + 1);
    for (int index = 0; index < VaultFormat.MAXIMUM_FILE_COUNT; index++) {
      items.add(new VaultItemViewModel(new UUID(0, index + 1L), "file-" + index, 0, Instant.EPOCH));
    }

    var accepted = new UnlockedVaultState("MyVault", items, 0, 256, null);
    assertEquals(VaultFormat.MAXIMUM_FILE_COUNT, accepted.items().size());

    items.add(
        new VaultItemViewModel(
            new UUID(0, VaultFormat.MAXIMUM_FILE_COUNT + 1L), "one-too-many", 0, Instant.EPOCH));
    assertThrows(
        IllegalArgumentException.class,
        () -> new UnlockedVaultState("MyVault", items, 0, 256, null));
  }

  private static void selectForTest(UnlockedVaultState state, UUID itemId) {
    assertNotNull(state.select(itemId));
  }
}
