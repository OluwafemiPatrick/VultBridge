package com.vultbridge.platform;

/** Reports sidecar lock contention using the one approved user-facing message. */
public final class VaultAlreadyOpenException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Creates the sanitized contention failure. */
  public VaultAlreadyOpenException() {
    super("Vault already open");
  }
}
