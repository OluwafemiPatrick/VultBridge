package com.vultbridge.service;

/**
 * Enumerates non-sensitive failure categories from which the UI can choose approved messages.
 *
 * <p>Raw exception text is intentionally excluded because it can disclose file names, paths, or
 * provider details.
 */
public enum JobFailureCategory {
  INPUT_REJECTED,
  VAULT_ALREADY_OPEN,
  UNABLE_TO_UNLOCK,
  FILESYSTEM,
  SECURITY,
  INTERNAL
}
