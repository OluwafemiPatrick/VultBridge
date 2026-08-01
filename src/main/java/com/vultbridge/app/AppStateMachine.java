package com.vultbridge.app;

import com.vultbridge.ui.UnlockedVaultState;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/** Enforces legal top-level UI transitions. It contains no secrets or vault data. */
public final class AppStateMachine {
  private final List<Consumer<AppState>> listeners = new ArrayList<>();
  private AppState state = AppState.initial();

  public AppState state() {
    return state;
  }

  public void addListener(Consumer<AppState> listener) {
    listeners.add(Objects.requireNonNull(listener, "listener"));
  }

  public void showCreateVault() {
    requireState(AppScreen.WELCOME, VaultSessionState.CLOSED, JobState.IDLE);
    transitionTo(AppState.closed(AppScreen.CREATE_VAULT, JobState.IDLE));
  }

  public void showOpenVault() {
    requireState(AppScreen.WELCOME, VaultSessionState.CLOSED, JobState.IDLE);
    transitionTo(AppState.closed(AppScreen.OPEN_VAULT, JobState.IDLE));
  }

  public void cancelVaultSetup() {
    requireIdle();
    if (state.screen() != AppScreen.CREATE_VAULT && state.screen() != AppScreen.OPEN_VAULT) {
      throw new IllegalStateException("Only a vault setup screen can be cancelled");
    }
    transitionTo(AppState.initial());
  }

  public void beginOperation() {
    requireIdle();
    if (state.screen() == AppScreen.WELCOME) {
      throw new IllegalStateException("No operation can begin on the welcome screen");
    }
    transitionTo(
        state
            .unlockedVault()
            .map(vault -> AppState.unlocked(vault, JobState.BUSY))
            .orElseGet(() -> AppState.closed(state.screen(), JobState.BUSY)));
  }

  public void failOperation() {
    requireBusy();
    transitionTo(
        state
            .unlockedVault()
            .map(vault -> AppState.unlocked(vault, JobState.IDLE))
            .orElseGet(() -> AppState.closed(state.screen(), JobState.IDLE)));
  }

  public void completeUnlock(UnlockedVaultState vaultState) {
    Objects.requireNonNull(vaultState, "vaultState");
    requireBusy();
    if (state.screen() != AppScreen.CREATE_VAULT && state.screen() != AppScreen.OPEN_VAULT) {
      throw new IllegalStateException("Unlock can complete only from a vault setup screen");
    }
    transitionTo(AppState.unlocked(vaultState.clearSelection(), JobState.IDLE));
  }

  public void selectItem(java.util.UUID itemId) {
    Objects.requireNonNull(itemId, "itemId");
    requireState(AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, JobState.IDLE);
    transitionTo(
        AppState.unlocked(state.unlockedVault().orElseThrow().select(itemId), JobState.IDLE));
  }

  public void clearSelection() {
    requireState(AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, JobState.IDLE);
    var vaultState = state.unlockedVault().orElseThrow();
    if (vaultState.hasSelection()) {
      transitionTo(AppState.unlocked(vaultState.clearSelection(), JobState.IDLE));
    }
  }

  public void replaceVaultMetadata(UnlockedVaultState vaultState) {
    Objects.requireNonNull(vaultState, "vaultState");
    requireState(AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, JobState.IDLE);
    transitionTo(AppState.unlocked(vaultState.clearSelection(), JobState.IDLE));
  }

  public void completeLock() {
    requireState(AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, JobState.BUSY);
    transitionTo(AppState.initial());
  }

  private void requireIdle() {
    if (state.jobState() != JobState.IDLE) {
      throw new IllegalStateException("The application is busy");
    }
  }

  private void requireBusy() {
    if (state.jobState() != JobState.BUSY) {
      throw new IllegalStateException("No application operation is active");
    }
  }

  private void requireState(
      AppScreen expectedScreen, VaultSessionState expectedSession, JobState expectedJobState) {
    if (state.screen() != expectedScreen
        || state.sessionState() != expectedSession
        || state.jobState() != expectedJobState) {
      throw new IllegalStateException(
          "The requested transition is not valid from the current state");
    }
  }

  private void transitionTo(AppState nextState) {
    state = nextState;
    List.copyOf(listeners).forEach(listener -> listener.accept(state));
  }
}
