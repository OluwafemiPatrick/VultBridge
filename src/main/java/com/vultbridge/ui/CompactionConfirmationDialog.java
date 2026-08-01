package com.vultbridge.ui;

import com.vultbridge.platform.FileDialogService;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Objects;
import javafx.geometry.Insets;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Window;

/** Safe Phase 1 confirmation shell for Compact and Replace. */
public final class CompactionConfirmationDialog {
  private final FileDialogService fileDialogs;
  private final SecureRandom random = new SecureRandom();

  public CompactionConfirmationDialog(FileDialogService fileDialogs) {
    this.fileDialogs = Objects.requireNonNull(fileDialogs, "fileDialogs");
  }

  public void show(Window owner, UnlockedVaultState vaultState) {
    Objects.requireNonNull(vaultState, "vaultState");
    String outputName =
        CompactionNameGenerator.generate(
            vaultState.vaultDisplayName(), Instant.now(), () -> random.nextInt(0x0100_0000));

    var dialog = new Dialog<ButtonType>();
    dialog.setTitle("Compact & Replace");
    dialog.setHeaderText("Create and validate a compacted replacement vault");
    if (owner != null) {
      dialog.initOwner(owner);
    }

    var destination = new Label("Choose a destination directory");
    destination.setWrapText(true);
    var availableSpace = new Label("Checked after the destination is chosen");
    var chooseButton = new javafx.scene.control.Button("Choose destination…");
    chooseButton.setOnAction(
        event ->
            fileDialogs
                .chooseCompactionDirectory(owner)
                .ifPresent(
                    selected -> {
                      destination.setText(selected.resolve(outputName).toString());
                      availableSpace.setText("Available space will be checked before writing.");
                    }));

    var details = new GridPane();
    details.getStyleClass().add("dialog-details");
    details.setHgap(14);
    details.setVgap(7);
    addDetail(details, 0, "Replacement filename", outputName);
    addDetail(
        details,
        1,
        "Required free space",
        "%s plus a safety margin"
            .formatted(ByteSizeFormatter.format(vaultState.physicalVaultBytes())));
    details.add(new Label("Destination"), 0, 2);
    details.add(destination, 1, 2);
    details.add(new Label("Available space"), 0, 3);
    details.add(availableSpace, 1, 3);

    var warningTitle =
        new Label("The current vault is deleted only after the replacement validates.");
    warningTitle.getStyleClass().add("warning-title");
    var warningText =
        new Label(
            String.join(
                " ",
                "If compaction or validation fails, the current vault remains unchanged.",
                "If source deletion fails after validation, both encrypted files remain.",
                "Deletion is not secure erasure."));
    warningText.setWrapText(true);
    var warning = new VBox(4, warningTitle, warningText);
    warning.getStyleClass().add("warning-panel");

    var content = new VBox(12, details, chooseButton, warning);
    content.setPadding(new Insets(4));
    content.setPrefWidth(540);
    dialog.getDialogPane().setContent(content);

    var startType = new ButtonType("Start compaction", ButtonBar.ButtonData.OK_DONE);
    dialog.getDialogPane().getButtonTypes().addAll(ButtonType.CANCEL, startType);
    dialog.getDialogPane().lookupButton(startType).setDisable(true);
    dialog
        .getDialogPane()
        .lookupButton(startType)
        .setAccessibleHelp("Compaction requires the encrypted vault engine.");
    dialog.showAndWait();
  }

  private static void addDetail(GridPane details, int row, String labelText, String valueText) {
    var label = new Label(labelText);
    label.getStyleClass().add("detail-label");
    var value = new Label(valueText);
    value.setWrapText(true);
    details.add(label, 0, row);
    details.add(value, 1, row);
  }
}
