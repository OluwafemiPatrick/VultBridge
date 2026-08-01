package com.vultbridge.app;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.ui.UnlockedVaultState;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AppStateTest {
  @Test
  void initialStateIsClosedAndIdleOnWelcomeScreen() {
    var state = AppState.initial();

    assertTrue(state.unlockedVault().isEmpty());
    assertFalse(state.canImport());
    assertFalse(state.canExport());
    assertFalse(state.canDelete());
    assertFalse(state.canCompact());
    assertFalse(state.canLock());
  }

  @Test
  void unlockedScreenRequiresUnlockedSessionAndMetadata() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppState(
                AppScreen.UNLOCKED_VAULT,
                VaultSessionState.CLOSED,
                JobState.IDLE,
                Optional.of(UnlockedVaultState.empty("MyVault", 256))));
  }

  @Test
  void unlockedSessionRequiresUnlockedScreenAndMetadata() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppState(
                AppScreen.WELCOME,
                VaultSessionState.UNLOCKED,
                JobState.IDLE,
                Optional.of(UnlockedVaultState.empty("MyVault", 256))));
  }

  @Test
  void closedStateRejectsUnlockedMetadata() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppState(
                AppScreen.WELCOME,
                VaultSessionState.CLOSED,
                JobState.IDLE,
                Optional.of(UnlockedVaultState.empty("MyVault", 256))));
  }
}
