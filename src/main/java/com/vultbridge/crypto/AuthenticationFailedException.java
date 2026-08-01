package com.vultbridge.crypto;

/**
 * Signals that authenticated decryption rejected ciphertext without exposing the failure detail.
 *
 * <p>Callers must treat wrong keys, nonces, associated data, truncation, and altered tags as the
 * same failure category. The exception never embeds provider messages or sensitive input.
 */
public final class AuthenticationFailedException extends Exception {
  private static final long serialVersionUID = 1L;

  AuthenticationFailedException() {
    super("Authentication failed");
  }
}
