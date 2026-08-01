package com.vultbridge.platform;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import javafx.stage.Window;

/** Native file and directory selections used by the UI. Selection alone never modifies a path. */
public interface FileDialogService {
  Optional<Path> chooseNewVault(Window owner);

  Optional<Path> chooseExistingVault(Window owner);

  List<Path> chooseImportFiles(Window owner);

  Optional<Path> chooseExportDestination(Window owner, String suggestedName);

  Optional<Path> chooseCompactionDirectory(Window owner);
}
