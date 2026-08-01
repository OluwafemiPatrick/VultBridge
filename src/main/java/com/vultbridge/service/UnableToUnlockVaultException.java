package com.vultbridge.service;

/** Reports every passphrase, authentication, or persisted-data unlock failure identically. */
public final class UnableToUnlockVaultException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Creates the one approved non-sensitive unlock failure. */
  public UnableToUnlockVaultException() {
    super("Unable to unlock this vault");
  }
}
