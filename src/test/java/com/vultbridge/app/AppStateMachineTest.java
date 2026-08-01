package com.vultbridge.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.ui.UnlockedVaultState;
import com.vultbridge.ui.VaultItemViewModel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AppStateMachineTest {
  private static final UUID ITEM_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");

  @Test
  void navigatesFromWelcomeToCreateAndBack() {
    var stateMachine = new AppStateMachine();

    stateMachine.showCreateVault();
    assertEquals(AppScreen.CREATE_VAULT, stateMachine.state().screen());

    stateMachine.cancelVaultSetup();
    assertEquals(AppState.initial(), stateMachine.state());
  }

  @Test
  void navigatesFromWelcomeToOpenAndBack() {
    var stateMachine = new AppStateMachine();

    stateMachine.showOpenVault();
    assertEquals(AppScreen.OPEN_VAULT, stateMachine.state().screen());

    stateMachine.cancelVaultSetup();
    assertEquals(AppState.initial(), stateMachine.state());
  }

  @Test
  void rejectsNavigationWhileBusy() {
    var stateMachine = new AppStateMachine();
    stateMachine.showCreateVault();
    stateMachine.beginOperation();

    assertThrows(IllegalStateException.class, stateMachine::cancelVaultSetup);
    assertEquals(JobState.BUSY, stateMachine.state().jobState());
  }

  @Test
  void reachesUnlockedScreenOnlyAfterSuccessfulOperationWithMetadata() {
    var stateMachine = new AppStateMachine();
    stateMachine.showOpenVault();

    assertThrows(
        IllegalStateException.class,
        () -> stateMachine.completeUnlock(UnlockedVaultState.empty("MyVault", 256)));

    stateMachine.beginOperation();
    stateMachine.completeUnlock(populatedVaultState());

    assertEquals(AppScreen.UNLOCKED_VAULT, stateMachine.state().screen());
    assertEquals(VaultSessionState.UNLOCKED, stateMachine.state().sessionState());
    assertEquals("MyVault", stateMachine.state().unlockedVault().orElseThrow().vaultDisplayName());
  }

  @Test
  void failedOperationReturnsToSameIdleScreen() {
    var stateMachine = new AppStateMachine();
    stateMachine.showOpenVault();
    stateMachine.beginOperation();

    stateMachine.failOperation();

    assertEquals(AppState.closed(AppScreen.OPEN_VAULT, JobState.IDLE), stateMachine.state());
  }

  @Test
  void selectsAndClearsAnExistingItem() {
    var stateMachine = unlockedStateMachine();

    stateMachine.selectItem(ITEM_ID);
    assertTrue(stateMachine.state().canExport());
    assertTrue(stateMachine.state().canDelete());

    stateMachine.clearSelection();
    assertFalse(stateMachine.state().canExport());
    assertFalse(stateMachine.state().canDelete());
  }

  @Test
  void rejectsSelectionOfAnUnknownItem() {
    var stateMachine = unlockedStateMachine();

    assertThrows(IllegalArgumentException.class, () -> stateMachine.selectItem(UUID.randomUUID()));
    assertFalse(stateMachine.state().unlockedVault().orElseThrow().hasSelection());
  }

  @Test
  void replacingMetadataClearsSelection() {
    var stateMachine = unlockedStateMachine();
    stateMachine.selectItem(ITEM_ID);

    stateMachine.replaceVaultMetadata(populatedVaultState().select(ITEM_ID));

    assertFalse(stateMachine.state().unlockedVault().orElseThrow().hasSelection());
  }

  @Test
  void busyStateDisablesUnlockedActionsWithoutDiscardingMetadata() {
    var stateMachine = unlockedStateMachine();
    stateMachine.selectItem(ITEM_ID);

    stateMachine.beginOperation();

    assertFalse(stateMachine.state().canImport());
    assertFalse(stateMachine.state().canExport());
    assertFalse(stateMachine.state().canDelete());
    assertFalse(stateMachine.state().canCompact());
    assertFalse(stateMachine.state().canLock());
    assertTrue(stateMachine.state().unlockedVault().isPresent());
  }

  @Test
  void lockingClearsAllUnlockedMetadata() {
    var stateMachine = unlockedStateMachine();
    stateMachine.selectItem(ITEM_ID);

    stateMachine.beginOperation();
    stateMachine.completeLock();

    assertEquals(AppState.initial(), stateMachine.state());
    assertTrue(stateMachine.state().unlockedVault().isEmpty());
  }

  @Test
  void notifiesListenersAfterEachTransition() {
    var stateMachine = new AppStateMachine();
    var observedStates = new ArrayList<AppState>();
    stateMachine.addListener(observedStates::add);

    stateMachine.showCreateVault();
    stateMachine.cancelVaultSetup();

    assertEquals(2, observedStates.size());
    assertEquals(AppState.initial(), observedStates.get(1));
  }

  private static AppStateMachine unlockedStateMachine() {
    var stateMachine = new AppStateMachine();
    stateMachine.showOpenVault();
    stateMachine.beginOperation();
    stateMachine.completeUnlock(populatedVaultState());
    return stateMachine;
  }

  private static UnlockedVaultState populatedVaultState() {
    var item =
        new VaultItemViewModel(ITEM_ID, "passport.pdf", 128, Instant.parse("2026-08-01T10:00:00Z"));
    return new UnlockedVaultState("MyVault", List.of(item), 128, 512, null);
  }
}
