package com.vultbridge.service;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * Groups the UI-thread callbacks associated with one submitted background job.
 *
 * <p>Exactly one terminal callback—success, failure, or cancellation—is selected by the manager.
 * Callback values must not contain secrets, plaintext data, file names, or complete paths.
 */
public record JobCallbacks<T>(
    Consumer<T> succeeded,
    Consumer<JobProgress> progressed,
    Consumer<JobFailureCategory> failed,
    Runnable cancelled) {
  public JobCallbacks {
    Objects.requireNonNull(succeeded, "succeeded");
    Objects.requireNonNull(progressed, "progressed");
    Objects.requireNonNull(failed, "failed");
    Objects.requireNonNull(cancelled, "cancelled");
  }
}
