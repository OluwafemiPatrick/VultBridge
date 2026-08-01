package com.vultbridge.service;

import com.vultbridge.platform.VaultAccessException;
import java.nio.file.Path;

/**
 * Enforces the externally visible filename contract for v1 vault service operations.
 *
 * <p>A v1 vault must have a non-empty base name followed by the exact lowercase {@code .vltb}
 * extension. Keeping this check inside the service boundary prevents programmatic callers from
 * bypassing the UI filter and creating or opening inconsistently named vault files. The policy
 * examines only the final path component and performs no filesystem access.
 */
final class VaultPathPolicy {
  private static final String EXTENSION = ".vltb";

  private VaultPathPolicy() {}

  /** Returns the validated final filename or rejects a noncanonical v1 vault path. */
  static String requireV1VaultFile(Path vaultPath) throws VaultAccessException {
    Path fileName = vaultPath.getFileName();
    if (fileName == null) {
      throw new VaultAccessException();
    }
    String value = fileName.toString();
    if (value.length() <= EXTENSION.length() || !value.endsWith(EXTENSION)) {
      throw new VaultAccessException();
    }
    return value;
  }
}
