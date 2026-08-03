package com.vultbridge.ui;

import com.vultbridge.service.CompactionPreview;
import java.nio.file.Path;
import java.util.Objects;
import javafx.geometry.Insets;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.Window;

/**
 * Presents the confirmation contract for the destructive Compact &amp; Replace workflow.
 *
 * <p>The dialog is metadata-only: the service has already performed read-only preflight, and this
 * class only displays its result and returns whether the user explicitly confirmed. It never
 * creates, reads, moves, or deletes a filesystem path.
 */
public final class CompactionConfirmationDialog {
  /** Creates the metadata-only confirmation dialog controller. */
  public CompactionConfirmationDialog() {}

  /** Displays the preflight result and returns {@code true} only after explicit confirmation. */
  public boolean show(Window owner, Path destinationDirectory, CompactionPreview preview) {
    Objects.requireNonNull(destinationDirectory, "destinationDirectory");
    Objects.requireNonNull(preview, "preview");
    var estimate = preview.estimate();

    var dialog = new Dialog<ButtonType>();
    dialog.setTitle("Compact & Replace");
    dialog.setHeaderText("Create and validate a compacted replacement vault");
    if (owner != null) {
      dialog.initOwner(owner);
    }

    var destination = new Label(destinationDirectory.toString());
    destination.setWrapText(true);

    var details = new GridPane();
    details.getStyleClass().add("dialog-details");
    details.setHgap(14);
    details.setVgap(7);
    addDetail(details, 0, "Replacement filename", preview.outputFileName());
    addDetail(
        details,
        1,
        "Current vault size",
        ByteSizeFormatter.format(estimate.sourcePhysicalVaultBytes()));
    addDetail(
        details, 2, "Live file data", ByteSizeFormatter.format(estimate.liveLogicalFileBytes()));
    addDetail(
        details,
        3,
        "Estimated replacement",
        ByteSizeFormatter.format(estimate.estimatedCandidateBytes()));
    addDetail(details, 4, "Safety margin", ByteSizeFormatter.format(estimate.safetyMarginBytes()));
    addDetail(
        details,
        5,
        "Required free space",
        ByteSizeFormatter.format(estimate.requiredDestinationBytes()));
    details.add(new Label("Destination"), 0, 6);
    details.add(destination, 1, 6);
    addDetail(
        details,
        7,
        "Available space (hint)",
        ByteSizeFormatter.format(estimate.usableDestinationBytes()));

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

    var content = new VBox(12, details, warning);
    content.setPadding(new Insets(4));
    content.setPrefWidth(540);
    dialog.getDialogPane().setContent(content);

    var startType = new ButtonType("Start compaction", ButtonBar.ButtonData.OK_DONE);
    dialog.getDialogPane().getButtonTypes().addAll(ButtonType.CANCEL, startType);
    dialog
        .getDialogPane()
        .lookupButton(startType)
        .setAccessibleHelp("Create, validate, and activate the encrypted replacement vault.");
    return dialog.showAndWait().filter(startType::equals).isPresent();
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
