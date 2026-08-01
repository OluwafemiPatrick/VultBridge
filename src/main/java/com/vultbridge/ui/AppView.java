package com.vultbridge.ui;

import com.vultbridge.app.AppState;
import com.vultbridge.app.AppStateMachine;
import com.vultbridge.app.JobState;
import com.vultbridge.app.VaultSessionState;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.platform.FileDialogService;
import com.vultbridge.platform.JavaFxFileDialogService;
import com.vultbridge.service.BackgroundJobManager;
import com.vultbridge.service.JobCallbacks;
import com.vultbridge.service.JobFailureCategory;
import com.vultbridge.service.JobHandle;
import com.vultbridge.service.JobPhase;
import com.vultbridge.service.JobProgress;
import com.vultbridge.service.VaultService;
import com.vultbridge.service.VaultSnapshot;
import java.nio.file.Path;
import java.util.List;
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
  private final FileDialogService fileDialogs;
  private final CompactionConfirmationDialog compactionDialog;
  private final BackgroundJobManager backgroundJobs;
  private final VaultService vaultService;
  private final Label securityState = new Label();
  private final Label operationStatus = new Label();
  private JobHandle activeJob;
  private boolean lockRequested;
  private boolean closed;

  /** Constructs the application shell and renders its initial state. */
  public AppView() {
    this(
        new JavaFxFileDialogService(),
        new BackgroundJobManager(Platform::runLater),
        new VaultService());
  }

  /** Test seam that retains the same ownership rules while replacing external boundaries. */
  AppView(
      FileDialogService fileDialogs,
      BackgroundJobManager backgroundJobs,
      VaultService vaultService) {
    this.fileDialogs = java.util.Objects.requireNonNull(fileDialogs, "fileDialogs");
    this.backgroundJobs = java.util.Objects.requireNonNull(backgroundJobs, "backgroundJobs");
    this.vaultService = java.util.Objects.requireNonNull(vaultService, "vaultService");
    compactionDialog = new CompactionConfirmationDialog(fileDialogs);
    getStyleClass().add("app-view");
    setTop(createHeader());
    stateMachine.addListener(this::render);
    render(stateMachine.state());
  }

  private HBox createHeader() {
    var brand = new Label("VultBridge");
    brand.getStyleClass().add("brand");
    operationStatus.setId("operation-status");
    var header = new HBox(12, brand, operationStatus, securityState);
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

    // Setup forms remain inert while create/open runs. The unlocked view disables every conflicting
    // action itself but deliberately keeps Lock available as the active-job cancellation path.
    setDisable(
        state.jobState() == JobState.BUSY && state.sessionState() != VaultSessionState.UNLOCKED);
    switch (state.screen()) {
      case WELCOME ->
          setCenter(new WelcomeView(stateMachine::showCreateVault, stateMachine::showOpenVault));
      case CREATE_VAULT ->
          setCenter(
              new CreateVaultView(fileDialogs, stateMachine::cancelVaultSetup, this::createVault));
      case OPEN_VAULT ->
          setCenter(
              new OpenVaultView(fileDialogs, stateMachine::cancelVaultSetup, this::openVault));
      case UNLOCKED_VAULT ->
          setCenter(
              new UnlockedVaultView(
                  state,
                  fileDialogs,
                  stateMachine::selectItem,
                  stateMachine::clearSelection,
                  this::lockVault,
                  this::showCompaction,
                  this::importFiles,
                  this::exportFile,
                  this::deleteFile));
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
    if (closed) {
      return;
    }
    closed = true;
    clearSensitiveState();
    lockRequested = false;
    backgroundJobs.close(java.time.Duration.ofSeconds(5), vaultService::close);
  }

  private void lockVault() {
    if (stateMachine.state().jobState() == JobState.BUSY) {
      lockRequested = true;
      operationStatus.setText("Locking when the current chunk is safe…");
      if (activeJob != null) {
        activeJob.requestCancellation();
      }
      return;
    }
    stateMachine.beginOperation();
    startLockJob();
  }

  private void startLockJob() {
    operationStatus.setText("Locking vault…");
    submit(
        context -> {
          if (vaultService.isOpen()) {
            vaultService.lock();
          }
          return null;
        },
        ignored -> {
          operationStatus.setText("");
          stateMachine.completeLock();
        },
        false);
  }

  private void showCompaction(UnlockedVaultState vaultState) {
    compactionDialog.show(getScene() == null ? null : getScene().getWindow(), vaultState);
  }

  private void createVault(Path path, SensitiveBytes passphrase) {
    submitUnlock(path, passphrase, true);
  }

  private void openVault(Path path, SensitiveBytes passphrase) {
    submitUnlock(path, passphrase, false);
  }

  private void submitUnlock(Path path, SensitiveBytes passphrase, boolean create) {
    stateMachine.beginOperation();
    operationStatus.setText(create ? "Creating vault…" : "Unlocking vault…");
    try {
      activeJob =
          backgroundJobs.submit(
              context -> {
                try (passphrase) {
                  context.reportProgress(new JobProgress(JobPhase.PREPARING, 0, 1));
                  return create
                      ? vaultService.create(path, passphrase)
                      : vaultService.open(path, passphrase);
                }
              },
              callbacks(
                  snapshot -> {
                    operationStatus.setText("");
                    stateMachine.completeUnlock(UnlockedVaultState.fromSnapshot(snapshot));
                  },
                  false));
    } catch (RuntimeException exception) {
      passphrase.close();
      stateMachine.failOperation();
      operationStatus.setText("Unable to start the operation.");
    }
  }

  private void importFiles(List<Path> sources) {
    beginVaultOperation(context -> vaultService.importFiles(sources, context));
  }

  private void deleteFile(String displayName) {
    beginVaultOperation(context -> vaultService.delete(displayName, context));
  }

  private void exportFile(String displayName, Path destination) {
    beginVaultOperation(context -> vaultService.export(displayName, destination, context));
  }

  private void beginVaultOperation(com.vultbridge.service.BackgroundJob<VaultSnapshot> operation) {
    stateMachine.beginOperation();
    operationStatus.setText("Working…");
    submit(
        operation,
        snapshot -> {
          operationStatus.setText("");
          stateMachine.completeVaultOperation(UnlockedVaultState.fromSnapshot(snapshot));
        },
        true);
  }

  private <T> void submit(
      com.vultbridge.service.BackgroundJob<T> operation,
      java.util.function.Consumer<T> success,
      boolean refreshVaultAfterFailure) {
    try {
      activeJob = backgroundJobs.submit(operation, callbacks(success, refreshVaultAfterFailure));
    } catch (RuntimeException exception) {
      stateMachine.failOperation();
      operationStatus.setText("Unable to start the operation.");
    }
  }

  private <T> JobCallbacks<T> callbacks(
      java.util.function.Consumer<T> success, boolean refreshVaultAfterFailure) {
    return new JobCallbacks<>(
        result -> finishJob(() -> success.accept(result)),
        this::showProgress,
        category ->
            finishJob(
                () ->
                    finishFailedVaultOperation(failureMessage(category), refreshVaultAfterFailure)),
        () ->
            finishJob(
                () ->
                    finishFailedVaultOperation("Operation cancelled.", refreshVaultAfterFailure)));
  }

  private void finishJob(Runnable normalCompletion) {
    activeJob = null;
    if (closed) {
      return;
    }
    if (lockRequested) {
      lockRequested = false;
      startLockJob();
      return;
    }
    normalCompletion.run();
  }

  private void finishFailedVaultOperation(String status, boolean refreshVaultMetadata) {
    if (!refreshVaultMetadata) {
      stateMachine.failOperation();
      operationStatus.setText(status);
      return;
    }

    // A multi-file import commits each accepted file independently. Refresh through the serialized
    // worker even when a later item fails so displayed metadata cannot lag authenticated state.
    operationStatus.setText(status + " Refreshing completed changes…");
    try {
      activeJob =
          backgroundJobs.submit(
              context -> vaultService.snapshot(),
              new JobCallbacks<>(
                  snapshot ->
                      finishJob(
                          () -> {
                            stateMachine.completeVaultOperation(
                                UnlockedVaultState.fromSnapshot(snapshot));
                            operationStatus.setText(status);
                          }),
                  ignored -> {},
                  ignored ->
                      finishJob(
                          () -> {
                            stateMachine.completeLock();
                            operationStatus.setText(status + " The vault was closed safely.");
                          }),
                  () ->
                      finishJob(
                          () -> {
                            stateMachine.completeLock();
                            operationStatus.setText(status + " The vault was closed safely.");
                          })));
    } catch (RuntimeException exception) {
      stateMachine.failOperation();
      operationStatus.setText(status);
    }
  }

  private void showProgress(JobProgress progress) {
    if (lockRequested || closed) {
      return;
    }
    operationStatus.setText(
        switch (progress.phase()) {
          case PREPARING -> "Preparing…";
          case PROCESSING -> "Processing…";
          case VERIFYING -> "Verifying…";
          case FINALIZING -> "Finalizing…";
        });
  }

  private static String failureMessage(JobFailureCategory category) {
    return switch (category) {
      case INPUT_REJECTED -> "The selected input is not supported.";
      case VAULT_ALREADY_OPEN -> "Vault already open.";
      case UNABLE_TO_UNLOCK -> "Unable to unlock this vault.";
      case FILESYSTEM -> "The filesystem operation could not be completed.";
      case SECURITY -> "Authentication or security validation failed.";
      case INTERNAL -> "The operation could not be completed.";
    };
  }
}
