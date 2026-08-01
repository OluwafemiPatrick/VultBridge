package com.vultbridge.ui;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.crypto.PassphraseRules;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.platform.FileDialogService;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.BiConsumer;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

/**
 * Presents the vault-open form and transfers validated input to the application controller.
 *
 * <p>Path selection does not read the selected vault. Valid input is encoded into a short-lived
 * owned buffer for the background service, while temporary character arrays and the visible
 * password control are cleared on every path.
 */
public final class OpenVaultView extends VBox implements SensitiveView {
  private final PasswordField passphraseField = new PasswordField();
  private final Label message = new Label();
  private final Runnable cancelAction;
  private final FileDialogService fileDialogs;
  private final BiConsumer<Path, SensitiveBytes> openAction;
  private final TextField pathField = new TextField("Choose an existing .vltb file");
  private Path selectedPath;

  /** Creates the form using an injected path chooser and navigation cancellation action. */
  public OpenVaultView(
      FileDialogService fileDialogs,
      Runnable cancelAction,
      BiConsumer<Path, SensitiveBytes> openAction) {
    this.fileDialogs = Objects.requireNonNull(fileDialogs, "fileDialogs");
    this.cancelAction = Objects.requireNonNull(cancelAction, "cancelAction");
    this.openAction = Objects.requireNonNull(openAction, "openAction");
    setId("open-vault-view");
    getStyleClass().addAll("content-view", "form-view", "compact-form-view");
    setPadding(new Insets(42, 72, 36, 72));
    setSpacing(10);

    var backButton = new Button("← Back");
    backButton.setId("open-back-button");
    backButton.getStyleClass().add("link-button");
    backButton.setOnAction(event -> cancel());

    var title = new Label("Unlock your vault");
    title.getStyleClass().add("screen-title");
    var description = new Label("Select a VultBridge vault and enter its passphrase.");
    description.getStyleClass().add("description");

    var pathLabel = new Label("Vault file");
    pathLabel.setLabelFor(pathField);
    pathField.setEditable(false);
    pathField.setId("existing-vault-path");
    var chooseButton = new Button("Choose…");
    chooseButton.setId("choose-existing-vault-button");
    chooseButton.setOnAction(event -> chooseVaultPath());
    var pathRow = new HBox(8, pathField, chooseButton);
    HBox.setHgrow(pathField, Priority.ALWAYS);

    var passphraseLabel = new Label("Passphrase");
    passphraseLabel.setLabelFor(passphraseField);
    passphraseField.setPromptText("Enter the vault passphrase");
    passphraseField.setId("existing-passphrase");

    message.getStyleClass().add("form-message");
    message.setWrapText(true);

    var cancelButton = new Button("Cancel");
    cancelButton.setOnAction(event -> cancel());
    var submitButton = new Button("Unlock vault");
    submitButton.setId("submit-open-vault-button");
    submitButton.getStyleClass().add("primary-button");
    submitButton.setDefaultButton(true);
    submitButton.setOnAction(event -> validateSubmission());
    var actions = new HBox(8, cancelButton, submitButton);
    actions.setAlignment(Pos.CENTER_RIGHT);

    getChildren()
        .addAll(
            backButton,
            title,
            description,
            pathLabel,
            pathRow,
            passphraseLabel,
            passphraseField,
            message,
            actions);
  }

  private void validateSubmission() {
    // Clear the visible field immediately and wipe the temporary mutable copy on every exit path.
    char[] passphrase = passphraseField.getText().toCharArray();
    clearSensitiveState();
    try {
      if (selectedPath == null) {
        showError("Choose an existing .vltb vault.");
      } else if (PassphraseRules.validate(passphrase)
          == PassphraseRules.ValidationResult.INVALID_LENGTH) {
        showError("Use " + PassphraseRules.requirementDescription() + ".");
      } else if (PassphraseRules.validate(passphrase)
          == PassphraseRules.ValidationResult.INVALID_CHARACTER) {
        showError("Only printable ASCII characters are accepted.");
      } else {
        message.getStyleClass().remove("error-message");
        SensitiveBytes encoded = PassphraseEncoding.encode(passphrase);
        boolean transferred = false;
        try {
          openAction.accept(selectedPath, encoded);
          transferred = true;
        } finally {
          if (!transferred) {
            encoded.close();
          }
        }
      }
    } finally {
      Arrays.fill(passphrase, '\0');
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
    message.setText("");
    selectedPath = null;
    pathField.setText("Choose an existing .vltb file");
    cancelAction.run();
  }

  private void chooseVaultPath() {
    fileDialogs
        .chooseExistingVault(getScene() == null ? null : getScene().getWindow())
        .ifPresent(
            path -> {
              selectedPath = path;
              pathField.setText(path.toString());
              message.setText("");
            });
  }

  // Removes passphrase text owned by this view.
  @Override
  public void clearSensitiveState() {
    passphraseField.clear();
  }
}
