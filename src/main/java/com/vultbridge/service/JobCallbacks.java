package com.vultbridge.service;

import java.util.Objects;
import java.util.function.Consumer;

/** UI-thread callbacks for one submitted job. Callback values must not contain secrets. */
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
