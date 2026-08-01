package com.vultbridge.ui;

import com.vultbridge.crypto.PassphraseRules;
import com.vultbridge.platform.FileDialogService;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

/**
 * Presents the Phase 1 vault-creation form and validates its user input.
 *
 * <p>The view selects a destination path without touching the filesystem. Until the encrypted vault
 * engine exists, valid submission produces an explanatory message rather than a placeholder file.
 * Temporary passphrase arrays are overwritten after validation.
 */
public final class CreateVaultView extends VBox implements SensitiveView {
  private final PasswordField passphraseField = new PasswordField();
  private final PasswordField confirmationField = new PasswordField();
  private final CheckBox acknowledgement =
      new CheckBox("I understand there is no recovery option.");
  private final Label message = new Label();
  private final Runnable cancelAction;
  private final FileDialogService fileDialogs;
  private final TextField pathField = new TextField("Choose a new .vltb file");
  private Path selectedPath;

  /** Creates the form using an injected path chooser and navigation cancellation action. */
  public CreateVaultView(FileDialogService fileDialogs, Runnable cancelAction) {
    this.fileDialogs = Objects.requireNonNull(fileDialogs, "fileDialogs");
    this.cancelAction = Objects.requireNonNull(cancelAction, "cancelAction");
    setId("create-vault-view");
    getStyleClass().addAll("content-view", "form-view");
    setPadding(new Insets(24, 48, 28, 48));
    setSpacing(10);

    var backButton = new Button("← Back");
    backButton.setId("create-back-button");
    backButton.getStyleClass().add("link-button");
    backButton.setOnAction(event -> cancel());

    var title = new Label("Create an encrypted vault");
    title.getStyleClass().add("screen-title");
    var description =
        new Label("Choose a location and protect the vault with a passphrase you can remember.");
    description.getStyleClass().add("description");

    pathField.setEditable(false);
    pathField.setId("new-vault-path");
    var chooseButton = new Button("Choose…");
    chooseButton.setId("choose-new-vault-button");
    chooseButton.setOnAction(event -> chooseVaultPath());
    var pathRow = new HBox(8, pathField, chooseButton);
    HBox.setHgrow(pathField, Priority.ALWAYS);

    passphraseField.setPromptText("8–64 characters");
    passphraseField.setId("new-passphrase");
    confirmationField.setPromptText("Enter the passphrase again");
    confirmationField.setId("confirm-passphrase");

    var fields = new GridPane();
    fields.setHgap(10);
    fields.setVgap(7);
    var pathLabel = new Label("Vault location");
    pathLabel.setLabelFor(pathField);
    var passphraseLabel = new Label("Passphrase");
    passphraseLabel.setLabelFor(passphraseField);
    var confirmationLabel = new Label("Confirm passphrase");
    confirmationLabel.setLabelFor(confirmationField);
    fields.add(pathLabel, 0, 0, 2, 1);
    fields.add(pathRow, 0, 1, 2, 1);
    fields.add(passphraseLabel, 0, 2);
    fields.add(confirmationLabel, 1, 2);
    fields.add(passphraseField, 0, 3);
    fields.add(confirmationField, 1, 3);
    GridPane.setHgrow(passphraseField, Priority.ALWAYS);
    GridPane.setHgrow(confirmationField, Priority.ALWAYS);

    var warning = new VBox(4);
    warning.getStyleClass().add("warning-panel");
    warning
        .getChildren()
        .addAll(
            new Label("Your passphrase cannot be recovered."),
            new Label("If you forget it, your files will be permanently inaccessible."),
            acknowledgement);

    message.getStyleClass().add("form-message");
    message.setWrapText(true);

    var cancelButton = new Button("Cancel");
    cancelButton.setOnAction(event -> cancel());
    var submitButton = new Button("Create vault");
    submitButton.setId("submit-create-vault-button");
    submitButton.getStyleClass().add("primary-button");
    submitButton.setDefaultButton(true);
    submitButton.setOnAction(event -> validateSubmission());
    var actions = new HBox(8, cancelButton, submitButton);
    actions.setAlignment(Pos.CENTER_RIGHT);

    getChildren().addAll(backButton, title, description, fields, warning, message, actions);
  }

  private void validateSubmission() {
    // Copy text only long enough to validate it, immediately clear the visible controls, and wipe
    // both mutable arrays in the finally block on every validation path.
    char[] passphrase = passphraseField.getText().toCharArray();
    char[] confirmation = confirmationField.getText().toCharArray();
    clearSensitiveState();
    try {
      if (selectedPath == null) {
        showError("Choose a new .vltb location.");
      } else if (!hasVaultExtension(selectedPath)) {
        showError("The vault filename must end with .vltb.");
      } else if (PassphraseRules.validate(passphrase)
          == PassphraseRules.ValidationResult.INVALID_LENGTH) {
        showError("Use 8–64 printable ASCII characters.");
      } else if (PassphraseRules.validate(passphrase)
          == PassphraseRules.ValidationResult.INVALID_CHARACTER) {
        showError("Only printable ASCII characters are accepted.");
      } else if (!Arrays.equals(passphrase, confirmation)) {
        showError("The passphrases do not match.");
      } else if (!acknowledgement.isSelected()) {
        showError("Acknowledge that the passphrase cannot be recovered.");
      } else {
        message.getStyleClass().remove("error-message");
        message.setText("Vault creation will be enabled when the encrypted vault engine is ready.");
      }
    } finally {
      Arrays.fill(passphrase, '\0');
      Arrays.fill(confirmation, '\0');
    }
  }

  private void showError(String text) {
    if (!message.getStyleClass().contains("error-message")) {
      message.getStyleClass().add("error-message");
    }
    message.setText(text);
  }

  private void cancel() {
    clearSensitiveState();
    acknowledgement.setSelected(false);
    message.setText("");
    selectedPath = null;
    pathField.setText("Choose a new .vltb file");
    cancelAction.run();
  }

  private void chooseVaultPath() {
    fileDialogs
        .chooseNewVault(getScene() == null ? null : getScene().getWindow())
        .ifPresent(
            path -> {
              selectedPath = path;
              pathField.setText(path.toString());
              message.setText("");
            });
  }

  private static boolean hasVaultExtension(Path path) {
    Path fileName = path.getFileName();
    return fileName != null && fileName.toString().endsWith(".vltb");
  }

  // Removes passphrase and confirmation text owned by this view.
  @Override
  public void clearSensitiveState() {
    passphraseField.clear();
    confirmationField.clear();
  }
}
