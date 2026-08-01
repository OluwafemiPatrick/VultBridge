package com.vultbridge.service;

/**
 * Provides cooperative cancellation and non-sensitive progress reporting to vault operations.
 *
 * <p>Implementations are supplied by the application-owned background worker. Vault services must
 * check cancellation only at boundaries that preserve the previous committed state and must never
 * place file names, paths, plaintext, or key material in progress values.
 */
public interface VaultOperationControl {
  /** Returns whether cancellation has been requested without changing operation state. */
  boolean isCancellationRequested();

  /** Stops the operation when cancellation has been requested at a safe boundary. */
  void checkpoint() throws JobCancelledException;

  /** Publishes one validated progress snapshot after checking cancellation. */
  void reportProgress(JobProgress progress) throws JobCancelledException;
}
