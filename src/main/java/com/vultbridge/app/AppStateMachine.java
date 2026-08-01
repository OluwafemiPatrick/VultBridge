package com.vultbridge.app;

import com.vultbridge.ui.UnlockedVaultState;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Owns the current {@link AppState} and enforces every legal top-level UI transition.
 *
 * <p>The state machine contains no passphrases, keys, plaintext, or filesystem paths. Views must
 * request transitions here instead of constructing arbitrary states, so busy-state and session
 * invariants remain centralized and testable.
 */
public final class AppStateMachine {
  private final List<Consumer<AppState>> listeners = new ArrayList<>();
  private AppState state = AppState.initial();

  /** Returns the current immutable state snapshot. */
  public AppState state() {
    return state;
  }

  /** Registers a listener that is called synchronously after each successful transition. */
  public void addListener(Consumer<AppState> listener) {
    listeners.add(Objects.requireNonNull(listener, "listener"));
  }

  /** Navigates from Welcome to the Create Vault form. */
  public void showCreateVault() {
    requireState(AppScreen.WELCOME, VaultSessionState.CLOSED, JobState.IDLE);
    transitionTo(AppState.closed(AppScreen.CREATE_VAULT, JobState.IDLE));
  }

  /** Navigates from Welcome to the Open Vault form. */
  public void showOpenVault() {
    requireState(AppScreen.WELCOME, VaultSessionState.CLOSED, JobState.IDLE);
    transitionTo(AppState.closed(AppScreen.OPEN_VAULT, JobState.IDLE));
  }

  /** Cancels either vault setup form and returns to the initial Welcome state. */
  public void cancelVaultSetup() {
    requireIdle();
    if (state.screen() != AppScreen.CREATE_VAULT && state.screen() != AppScreen.OPEN_VAULT) {
      throw new IllegalStateException("Only a vault setup screen can be cancelled");
    }
    transitionTo(AppState.initial());
  }

  /** Marks the current screen busy before its asynchronous operation is submitted. */
  public void beginOperation() {
    requireIdle();
    if (state.screen() == AppScreen.WELCOME) {
      throw new IllegalStateException("No operation can begin on the welcome screen");
    }
    // Preserve unlocked metadata while changing only the orthogonal job-state dimension.
    transitionTo(
        state
            .unlockedVault()
            .map(vault -> AppState.unlocked(vault, JobState.BUSY))
            .orElseGet(() -> AppState.closed(state.screen(), JobState.BUSY)));
  }

  /** Restores the current screen to idle after a failed or cancelled operation. */
  public void failOperation() {
    requireBusy();
    transitionTo(
        state
            .unlockedVault()
            .map(vault -> AppState.unlocked(vault, JobState.IDLE))
            .orElseGet(() -> AppState.closed(state.screen(), JobState.IDLE)));
  }

  /** Completes a create/open operation and enters a real metadata-backed unlocked session. */
  public void completeUnlock(UnlockedVaultState vaultState) {
    Objects.requireNonNull(vaultState, "vaultState");
    requireBusy();
    if (state.screen() != AppScreen.CREATE_VAULT && state.screen() != AppScreen.OPEN_VAULT) {
      throw new IllegalStateException("Unlock can complete only from a vault setup screen");
    }
    transitionTo(AppState.unlocked(vaultState.clearSelection(), JobState.IDLE));
  }

  /** Selects a vault item while the unlocked session is idle. */
  public void selectItem(java.util.UUID itemId) {
    Objects.requireNonNull(itemId, "itemId");
    requireState(AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, JobState.IDLE);
    transitionTo(
        AppState.unlocked(state.unlockedVault().orElseThrow().select(itemId), JobState.IDLE));
  }

  /** Clears the current file selection without changing vault metadata. */
  public void clearSelection() {
    requireState(AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, JobState.IDLE);
    var vaultState = state.unlockedVault().orElseThrow();
    if (vaultState.hasSelection()) {
      transitionTo(AppState.unlocked(vaultState.clearSelection(), JobState.IDLE));
    }
  }

  /** Replaces displayed vault metadata and deliberately discards any stale selection. */
  public void replaceVaultMetadata(UnlockedVaultState vaultState) {
    Objects.requireNonNull(vaultState, "vaultState");
    requireState(AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, JobState.IDLE);
    transitionTo(AppState.unlocked(vaultState.clearSelection(), JobState.IDLE));
  }

  /** Completes an active lock operation and returns to the initial closed state. */
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
    // Iterate over a snapshot so a listener can safely register another listener during delivery.
    List.copyOf(listeners).forEach(listener -> listener.accept(state));
  }
}
