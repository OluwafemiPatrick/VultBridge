package com.vultbridge.service;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Package-private source-unlink boundary used to exercise post-validation deletion failures.
 *
 * <p>The production implementation is the ordinary filesystem delete operation. It is kept behind
 * this narrow boundary so tests can prove that a validated replacement remains active when source
 * removal fails, without weakening the identity check or changing filesystem permissions.
 */
@FunctionalInterface
interface CompactionSourceRemover {
  /** Removes exactly the path supplied by the service. */
  void remove(Path sourcePath) throws IOException;
}
