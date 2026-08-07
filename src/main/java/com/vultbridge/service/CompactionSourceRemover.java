package com.vultbridge.service;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Package-private source-removal capability used only after replacement validation.
 *
 * <p>The default service policy is fail-closed retention because Java has no portable conditional
 * unlink operation. A platform adapter may be supplied only after it can prove that it removes the
 * expected source inode rather than a competing pathname occupant.
 */
@FunctionalInterface
interface CompactionSourceRemover {
  /** Removes the expected source and returns whether removal actually succeeded. */
  boolean remove(Path sourcePath) throws IOException;

  /** Returns the production fail-closed policy, which deliberately retains the source. */
  static CompactionSourceRemover retainSource() {
    return path -> false;
  }
}
