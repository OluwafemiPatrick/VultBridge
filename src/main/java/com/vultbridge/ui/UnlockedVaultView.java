package com.vultbridge.ui;

import com.vultbridge.app.AppState;
import com.vultbridge.platform.FileDialogService;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.SelectionMode;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

/**
 * Renders the unlocked vault as a flat, sortable, metadata-only file table.
 *
 * <p>Action availability is derived from {@link AppState}; selection changes are sent back through
 * callbacks rather than mutating application state locally. Plaintext file contents never enter
 * this view.
 */
public final class UnlockedVaultView extends BorderPane {
  private static final DateTimeFormatter IMPORTED_AT_FORMAT =
      DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).withZone(ZoneId.systemDefault());

  private final FileDialogService fileDialogs;
  private final UnlockedVaultState vaultState;
  private final Label message = new Label();

  /** Creates the unlocked screen from one validated state snapshot and its UI actions. */
  public UnlockedVaultView(
      AppState state,
      FileDialogService fileDialogs,
      Consumer<UUID> selectItem,
      Runnable clearSelection,
      Runnable lockVault,
      Consumer<UnlockedVaultState> showCompaction) {
    Objects.requireNonNull(state, "state");
    this.fileDialogs = Objects.requireNonNull(fileDialogs, "fileDialogs");
    Objects.requireNonNull(selectItem, "selectItem");
    Objects.requireNonNull(clearSelection, "clearSelection");
    Objects.requireNonNull(lockVault, "lockVault");
    Objects.requireNonNull(showCompaction, "showCompaction");
    vaultState = state.unlockedVault().orElseThrow();

    setId("unlocked-vault-view");
    getStyleClass().addAll("content-view", "vault-view");
    setPadding(new Insets(14, 18, 14, 18));

    setTop(createTopSection(state, lockVault));
    setCenter(createFileTable(selectItem, clearSelection));
    setBottom(createActionBar(state, showCompaction));
  }

  private VBox createTopSection(AppState state, Runnable lockVault) {
    var title = new Label(vaultState.vaultDisplayName());
    title.getStyleClass().add("screen-title");
    var subtitle = new Label("Unlocked vault");
    subtitle.getStyleClass().add("description");
    var heading = new VBox(1, title, subtitle);

    var lockButton = new Button("Lock vault");
    lockButton.setId("lock-vault-button");
    lockButton.setDisable(!state.canLock());
    lockButton.setOnAction(event -> lockVault.run());
    var toolbar = new HBox(12, heading, lockButton);
    toolbar.setAlignment(Pos.CENTER_LEFT);
    HBox.setHgrow(heading, Priority.ALWAYS);

    var summaries = new HBox(8);
    summaries.getChildren().add(summary("Files", vaultState.items().size() + " of 10,000"));
    summaries
        .getChildren()
        .add(
            summary("Live file data", ByteSizeFormatter.format(vaultState.liveLogicalFileBytes())));
    summaries
        .getChildren()
        .add(summary("Vault size", ByteSizeFormatter.format(vaultState.physicalVaultBytes())));
    summaries
        .getChildren()
        .add(
            summary(
                "Live-data limit",
                ByteSizeFormatter.format(vaultState.liveLogicalFileBytes()) + " of 100 GiB"));
    summaries.getChildren().forEach(child -> HBox.setHgrow(child, Priority.ALWAYS));

    message.getStyleClass().add("form-message");
    message.setWrapText(true);
    return new VBox(9, toolbar, summaries, message);
  }

  private TableView<VaultItemViewModel> createFileTable(
      Consumer<UUID> selectItem, Runnable clearSelection) {
    var table = new TableView<VaultItemViewModel>();
    table.setId("vault-file-table");
    table.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
    table.setPlaceholder(
        new Label(
            "This vault is empty. Import regular files to begin; folders and symbolic links are not supported."));

    var nameColumn = new TableColumn<VaultItemViewModel, String>("Name");
    nameColumn.setCellValueFactory(
        cell -> new ReadOnlyStringWrapper(cell.getValue().displayName()));
    nameColumn.setPrefWidth(330);

    var sizeColumn = new TableColumn<VaultItemViewModel, String>("Size");
    sizeColumn.setCellValueFactory(
        cell ->
            new ReadOnlyStringWrapper(
                ByteSizeFormatter.format(cell.getValue().logicalSizeBytes())));
    sizeColumn.setPrefWidth(110);

    var importedColumn = new TableColumn<VaultItemViewModel, String>("Imported");
    importedColumn.setCellValueFactory(
        cell ->
            new ReadOnlyStringWrapper(IMPORTED_AT_FORMAT.format(cell.getValue().importedAtUtc())));
    importedColumn.setPrefWidth(190);

    table.getColumns().add(nameColumn);
    table.getColumns().add(sizeColumn);
    table.getColumns().add(importedColumn);
    table.setItems(FXCollections.observableArrayList(vaultState.items()));
    vaultState.selectedItem().ifPresent(table.getSelectionModel()::select);
    // Mirror JavaFX selection into the immutable application state while avoiding feedback when the
    // table is initialized from an already-selected snapshot.
    table
        .getSelectionModel()
        .selectedItemProperty()
        .addListener(
            (observable, previous, selected) -> {
              if (selected == null) {
                clearSelection.run();
              } else if (!selected.itemId().equals(vaultState.selectedItemId())) {
                selectItem.accept(selected.itemId());
              }
            });
    return table;
  }

  private HBox createActionBar(AppState state, Consumer<UnlockedVaultState> showCompaction) {
    var compactButton = new Button("Compact & Replace");
    compactButton.setId("compact-vault-button");
    compactButton.setDisable(!state.canCompact());
    compactButton.setOnAction(event -> showCompaction.accept(vaultState));

    var importButton = new Button("Import files");
    importButton.setId("import-files-button");
    importButton.getStyleClass().add("primary-button");
    importButton.setDisable(!state.canImport());
    importButton.setOnAction(event -> chooseImports());

    var exportButton = new Button("Export");
    exportButton.setId("export-file-button");
    exportButton.setDisable(!state.canExport());
    exportButton.setOnAction(event -> chooseExport());

    var deleteButton = new Button("Delete");
    deleteButton.setId("delete-file-button");
    deleteButton.setDisable(!state.canDelete());
    deleteButton.setOnAction(event -> showDeleteConfirmation());

    var actions = new HBox(8, compactButton, importButton, exportButton, deleteButton);
    actions.setAlignment(Pos.CENTER_RIGHT);
    actions.setPadding(new Insets(10, 0, 0, 0));
    return actions;
  }

  private void chooseImports() {
    var selected = fileDialogs.chooseImportFiles(getScene().getWindow());
    if (!selected.isEmpty()) {
      message.setText(
          selected.size()
              + (selected.size() == 1 ? " file selected. " : " files selected. ")
              + "Import will be enabled when the encrypted vault engine is ready.");
    }
  }

  private void chooseExport() {
    vaultState
        .selectedItem()
        .flatMap(
            selected ->
                fileDialogs.chooseExportDestination(getScene().getWindow(), selected.displayName()))
        .ifPresent(
            ignored ->
                message.setText(
                    "Export will be enabled when the encrypted vault engine is ready."));
  }

  private void showDeleteConfirmation() {
    var alert = new Alert(Alert.AlertType.CONFIRMATION);
    alert.initOwner(getScene().getWindow());
    alert.setTitle("Delete file");
    alert.setHeaderText("Remove the selected file from the vault?");
    alert.setContentText(
        "Deletion removes the item from the file list but does not immediately shrink the physical vault file.");
    var acknowledge = new ButtonType("Acknowledge", ButtonBar.ButtonData.OK_DONE);
    alert.getButtonTypes().setAll(ButtonType.CANCEL, acknowledge);
    // Phase 1 confirms semantics but does not pretend that a manifest mutation occurred.
    if (alert.showAndWait().filter(acknowledge::equals).isPresent()) {
      message.setText("Deletion will be enabled when the encrypted vault engine is ready.");
    }
  }

  private static VBox summary(String labelText, String valueText) {
    var label = new Label(labelText);
    label.getStyleClass().add("summary-label");
    var value = new Label(valueText);
    value.getStyleClass().add("summary-value");
    var summary = new VBox(2, label, value);
    summary.getStyleClass().add("summary-card");
    summary.setMaxWidth(Double.MAX_VALUE);
    return summary;
  }
}
