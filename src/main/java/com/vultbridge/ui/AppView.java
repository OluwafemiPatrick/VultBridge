package com.vultbridge.ui;

import com.vultbridge.app.AppState;
import com.vultbridge.app.AppStateMachine;
import com.vultbridge.app.JobState;
import com.vultbridge.app.VaultSessionState;
import com.vultbridge.platform.FileDialogService;
import com.vultbridge.platform.JavaFxFileDialogService;
import com.vultbridge.service.BackgroundJobManager;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;

/**
 * Root JavaFX container that coordinates navigation, dialogs, and application-owned services.
 *
 * <p>Child views request navigation through {@link AppStateMachine}; they never replace scenes or
 * imply that an unavailable vault operation succeeded. This view also owns cleanup of sensitive
 * controls and the background worker.
 */
public final class AppView extends BorderPane implements AutoCloseable {
  private final AppStateMachine stateMachine = new AppStateMachine();
  private final FileDialogService fileDialogs = new JavaFxFileDialogService();
  private final CompactionConfirmationDialog compactionDialog =
      new CompactionConfirmationDialog(fileDialogs);
  private final BackgroundJobManager backgroundJobs = new BackgroundJobManager(Platform::runLater);
  private final Label securityState = new Label();

  /** Constructs the application shell and renders its initial state. */
  public AppView() {
    getStyleClass().add("app-view");
    setTop(createHeader());
    stateMachine.addListener(this::render);
    render(stateMachine.state());
  }

  private HBox createHeader() {
    var brand = new Label("VultBridge");
    brand.getStyleClass().add("brand");
    var header = new HBox(12, brand, securityState);
    header.getStyleClass().add("app-header");
    header.setAlignment(Pos.CENTER_LEFT);
    header.setPadding(new Insets(0, 20, 0, 20));
    HBox.setHgrow(brand, Priority.ALWAYS);
    return header;
  }

  private void render(AppState state) {
    // Clear the outgoing view before detaching it so passphrase controls do not survive navigation.
    clearSensitiveState();
    securityState.setText(
        state.sessionState() == VaultSessionState.UNLOCKED
            ? "●  Vault unlocked"
            : "●  No vault open");
    securityState
        .getStyleClass()
        .setAll(
            state.sessionState() == VaultSessionState.UNLOCKED
                ? "security-state-unlocked"
                : "security-state");

    // Busy state disables the complete content tree, preventing conflicting user operations.
    setDisable(state.jobState() == JobState.BUSY);
    switch (state.screen()) {
      case WELCOME ->
          setCenter(new WelcomeView(stateMachine::showCreateVault, stateMachine::showOpenVault));
      case CREATE_VAULT ->
          setCenter(new CreateVaultView(fileDialogs, stateMachine::cancelVaultSetup));
      case OPEN_VAULT -> setCenter(new OpenVaultView(fileDialogs, stateMachine::cancelVaultSetup));
      case UNLOCKED_VAULT ->
          setCenter(
              new UnlockedVaultView(
                  state,
                  fileDialogs,
                  stateMachine::selectItem,
                  stateMachine::clearSelection,
                  this::lockVault,
                  this::showCompaction));
    }
  }

  /** Clears any sensitive input still owned by the current child view. */
  public void clearSensitiveState() {
    Node currentView = getCenter();
    if (currentView instanceof SensitiveView sensitiveView) {
      sensitiveView.clearSensitiveState();
    }
  }

  // Cancels active work at its next checkpoint and releases application-owned worker threads.
  @Override
  public void close() {
    clearSensitiveState();
    backgroundJobs.close();
  }

  private void lockVault() {
    // Phase 1 owns metadata only, so locking is synchronous until a real session exists.
    stateMachine.beginOperation();
    stateMachine.completeLock();
  }

  private void showCompaction(UnlockedVaultState vaultState) {
    compactionDialog.show(getScene() == null ? null : getScene().getWindow(), vaultState);
  }
}
