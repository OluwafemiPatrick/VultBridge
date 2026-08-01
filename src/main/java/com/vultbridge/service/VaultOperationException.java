package com.vultbridge.service;

import java.util.Objects;

/**
 * Carries one approved non-sensitive failure category across the vault-service boundary.
 *
 * <p>The exception intentionally has no message, cause, or writable stack trace. Filesystem and
 * cryptographic exceptions can contain paths, file names, or provider details and must be reduced
 * to a category before they can reach UI callbacks.
 */
public final class VaultOperationException extends Exception {
  private static final long serialVersionUID = 1L;
  private final JobFailureCategory category;
  private final boolean sessionInvalidated;

  /** Creates a sanitized operation failure containing only its approved category. */
  public VaultOperationException(JobFailureCategory category) {
    this(category, false);
  }

  private VaultOperationException(JobFailureCategory category, boolean sessionInvalidated) {
    super(null, null, false, false);
    this.category = Objects.requireNonNull(category, "category");
    this.sessionInvalidated = sessionInvalidated;
  }

  /** Returns the only failure information permitted to cross into the UI layer. */
  public JobFailureCategory category() {
    return category;
  }

  /** Returns whether the service must close and reopen before any further vault operation. */
  public boolean sessionInvalidated() {
    return sessionInvalidated;
  }

  static VaultOperationException invalidatedSession(JobFailureCategory category) {
    return new VaultOperationException(category, true);
  }
}
