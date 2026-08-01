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

/** Root JavaFX container. Child views request navigation through the state machine. */
public final class AppView extends BorderPane implements AutoCloseable {
  private final AppStateMachine stateMachine = new AppStateMachine();
  private final FileDialogService fileDialogs = new JavaFxFileDialogService();
  private final CompactionConfirmationDialog compactionDialog =
      new CompactionConfirmationDialog(fileDialogs);
  private final BackgroundJobManager backgroundJobs = new BackgroundJobManager(Platform::runLater);
  private final Label securityState = new Label();

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

  /** Cancels active work at its next checkpoint and releases application-owned worker threads. */
  @Override
  public void close() {
    clearSensitiveState();
    backgroundJobs.close();
  }

  private void lockVault() {
    stateMachine.beginOperation();
    stateMachine.completeLock();
  }

  private void showCompaction(UnlockedVaultState vaultState) {
    compactionDialog.show(getScene() == null ? null : getScene().getWindow(), vaultState);
  }
}
