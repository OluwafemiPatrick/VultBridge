package com.vultbridge.vault;

/**
 * Reports malformed, unauthenticated, truncated, or inconsistent persisted vault data.
 *
 * <p>The exception deliberately exposes one fixed non-sensitive message and retains no underlying
 * exception, path, record identifier, filename, or parser detail. Internal components may use it
 * for expected validation failures without allowing untrusted persisted content to cross service or
 * UI boundaries.
 */
public final class VaultDataException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Creates the single sanitized persisted-data failure used by the vault engine. */
  public VaultDataException() {
    super("Vault data is invalid");
  }
}
