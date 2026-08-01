package com.vultbridge.app;

import com.vultbridge.ui.UnlockedVaultState;
import java.util.Objects;
import java.util.Optional;

/** Immutable, non-sensitive state used to decide which top-level view is visible. */
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

    boolean unlockedScreen = screen == AppScreen.UNLOCKED_VAULT;
    boolean unlockedSession = sessionState == VaultSessionState.UNLOCKED;
    boolean hasUnlockedMetadata = unlockedVault.isPresent();
    if (unlockedScreen != unlockedSession || unlockedSession != hasUnlockedMetadata) {
      throw new IllegalArgumentException(
          "The unlocked screen, session, and metadata must always exist together");
    }
  }

  public static AppState initial() {
    return closed(AppScreen.WELCOME, JobState.IDLE);
  }

  public static AppState closed(AppScreen screen, JobState jobState) {
    return new AppState(screen, VaultSessionState.CLOSED, jobState, Optional.empty());
  }

  public static AppState unlocked(UnlockedVaultState vaultState, JobState jobState) {
    return new AppState(
        AppScreen.UNLOCKED_VAULT, VaultSessionState.UNLOCKED, jobState, Optional.of(vaultState));
  }

  public boolean canImport() {
    return isIdleUnlocked();
  }

  public boolean canExport() {
    return isIdleUnlocked() && unlockedVault.orElseThrow().hasSelection();
  }

  public boolean canDelete() {
    return canExport();
  }

  public boolean canCompact() {
    return isIdleUnlocked() && unlockedVault.orElseThrow().hasFiles();
  }

  public boolean canLock() {
    return isIdleUnlocked();
  }

  private boolean isIdleUnlocked() {
    return sessionState == VaultSessionState.UNLOCKED && jobState == JobState.IDLE;
  }
}
