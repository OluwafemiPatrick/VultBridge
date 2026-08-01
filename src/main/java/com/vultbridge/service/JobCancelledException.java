package com.vultbridge.service;

/**
 * Internal control-flow signal raised when a job reaches a cooperative cancellation boundary.
 *
 * <p>The manager consumes this exception and delivers the cancellation callback; it is not shown to
 * users or logged as an operational failure.
 */
public final class JobCancelledException extends Exception {
  private static final long serialVersionUID = 1L;

  JobCancelledException() {
    super("Background operation cancelled");
  }
}
