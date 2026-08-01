package com.vultbridge.platform;

/**
 * Reports an unusable vault or lock path without retaining filesystem details.
 *
 * <p>The exception contains no path or underlying cause so it is safe to cross application and UI
 * boundaries.
 */
public final class VaultAccessException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Creates the sanitized filesystem-access failure. */
  public VaultAccessException() {
    super("Unable to access this vault");
  }
}
