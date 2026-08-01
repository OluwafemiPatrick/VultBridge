package com.vultbridge.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
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

  private static void selectForTest(UnlockedVaultState state, UUID itemId) {
    assertNotNull(state.select(itemId));
  }
}
