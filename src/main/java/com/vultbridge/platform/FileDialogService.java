package com.vultbridge.platform;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import javafx.stage.Window;

/**
 * Defines native file and directory selections requested by the UI.
 *
 * <p>This boundary returns user-selected paths only. Choosing a path must never create, read,
 * overwrite, move, or delete the target; those guarantees belong to later filesystem services.
 */
public interface FileDialogService {
  /** Prompts for the destination filename of a new vault. */
  Optional<Path> chooseNewVault(Window owner);

  /** Prompts for an existing vault file to open. */
  Optional<Path> chooseExistingVault(Window owner);

  /** Prompts for one or more regular files that the user wants to import. */
  List<Path> chooseImportFiles(Window owner);

  /** Prompts for an explicit export destination using the provided safe suggested filename. */
  Optional<Path> chooseExportDestination(Window owner, String suggestedName);

  /** Prompts for the directory in which a compacted replacement candidate will be created. */
  Optional<Path> chooseCompactionDirectory(Window owner);
}
