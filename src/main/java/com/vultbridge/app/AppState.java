package com.vultbridge.app;

import com.vultbridge.ui.UnlockedVaultState;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable, non-sensitive snapshot of the application UI state.
 *
 * <p>The screen, vault-session state, active-job state, and unlocked metadata move together under
 * strict invariants. In particular, the unlocked screen cannot exist without an unlocked session
 * and metadata, preventing navigation from being mistaken for a successful vault operation.
 */
public record AppState(
    AppScreen screen,
    VaultSessionState sessionState,
    JobState jobState,
    Optional<UnlockedVaultState> unlockedVault) {
  public AppState {
    Objects.requireNonNull(screen, "screen");
    Objects.requireNonNull(sessionState, "sessionState");
    Objects.requireNonNull(jobState, "jobState");
    Objects.requireNonNull(unlockedVault, "unlockedVault");

    // These three values represent one security boundary and may never disagree.
    boolean unlockedScreen = screen == AppScreen.UNLOCKED_VAULT;
    boolean unlockedSession = sessionState == VaultSessionState.UNLOCKED;
    boolean hasUnlockedMetadata = unlockedVault.isPresent();
    if (unlockedScreen != unlockedSession || unlockedSession != hasUnlockedMetadata) {
      throw new IllegalArgumentException(
          "The unlocked screen, session, and metadata must always exist together");
    }
  }

  /** Returns the initial state shown before any vault has been selected. */
  public static AppState initial() {
    return closed(AppScreen.WELCOME, JobState.IDLE);
  }

  /** Creates a state with no unlocked vault session. */
  public static AppState closed(AppScreen screen, JobState jobState) {
    return new AppState(screen, VaultSessionState.CLOSED, jobState, Optional.empty());
  }

  /** Creates an unlocked-screen state backed by validated, metadata-only vault state. */
  public static AppState unlocked(UnlockedVaultState vaultState, JobState jobState) {
    return new AppState(
        AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, jobState, Optional.of(vaultState));
  }

  /** Returns whether a new import operation may start in this state. */
  public boolean canImport() {
    return isIdleUnlocked();
  }

  /** Returns whether the currently selected item may be exported. */
  public boolean canExport() {
    return isIdleUnlocked() && unlockedVault.orElseThrow().hasSelection();
  }

  /** Returns whether the currently selected item may be logically deleted. */
  public boolean canDelete() {
    return canExport();
  }

  /** Returns whether compaction is available for the current vault. */
  public boolean canCompact() {
    return isIdleUnlocked() && unlockedVault.orElseThrow().hasFiles();
  }

  /** Returns whether the unlocked vault can be locked without conflicting with active work. */
  public boolean canLock() {
    return isIdleUnlocked();
  }

  private boolean isIdleUnlocked() {
    return sessionState == VaultSessionState.UNLOCKED && jobState == JobState.IDLE;
  }
}
