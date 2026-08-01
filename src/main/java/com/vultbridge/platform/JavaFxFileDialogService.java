package com.vultbridge.platform;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Window;

/**
 * Implements {@link FileDialogService} with JavaFX platform-owned chooser dialogs.
 *
 * <p>Each method translates a confirmed JavaFX {@code File} into a {@link Path}; cancellation is
 * represented by an empty optional or list. No method performs filesystem I/O itself.
 */
public final class JavaFxFileDialogService implements FileDialogService {
  private static final FileChooser.ExtensionFilter VAULT_FILTER =
      new FileChooser.ExtensionFilter("VultBridge vault (*.vltb)", "*.vltb");

  // Shows a save-style chooser for a new .vltb filename.
  @Override
  public Optional<Path> chooseNewVault(Window owner) {
    var chooser = new FileChooser();
    chooser.setTitle("Create VultBridge vault");
    chooser.setInitialFileName("MyVault.vltb");
    chooser.getExtensionFilters().add(VAULT_FILTER);
    var selected = chooser.showSaveDialog(owner);
    return selected == null ? Optional.empty() : Optional.of(selected.toPath());
  }

  // Shows an open-style chooser restricted to existing .vltb files.
  @Override
  public Optional<Path> chooseExistingVault(Window owner) {
    var chooser = new FileChooser();
    chooser.setTitle("Open VultBridge vault");
    chooser.getExtensionFilters().add(VAULT_FILTER);
    var selected = chooser.showOpenDialog(owner);
    return selected == null ? Optional.empty() : Optional.of(selected.toPath());
  }

  // Shows a multi-select file chooser for import candidates.
  @Override
  public List<Path> chooseImportFiles(Window owner) {
    var chooser = new FileChooser();
    chooser.setTitle("Import regular files");
    var selected = chooser.showOpenMultipleDialog(owner);
    if (selected == null) {
      return List.of();
    }
    return selected.stream().map(java.io.File::toPath).toList();
  }

  // Shows a save-style chooser for one explicit export destination.
  @Override
  public Optional<Path> chooseExportDestination(Window owner, String suggestedName) {
    var chooser = new FileChooser();
    chooser.setTitle("Choose export destination");
    chooser.setInitialFileName(suggestedName);
    var selected = chooser.showSaveDialog(owner);
    return selected == null ? Optional.empty() : Optional.of(selected.toPath());
  }

  // Shows a directory chooser for a compacted vault candidate.
  @Override
  public Optional<Path> chooseCompactionDirectory(Window owner) {
    var chooser = new DirectoryChooser();
    chooser.setTitle("Choose compacted vault destination");
    var selected = chooser.showDialog(owner);
    return selected == null ? Optional.empty() : Optional.of(selected.toPath());
  }
}
