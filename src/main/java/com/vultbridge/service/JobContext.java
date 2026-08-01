package com.vultbridge.service;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * Supplies cooperative cancellation and typed progress reporting to a running job.
 *
 * <p>The context is scoped to one submission. Progress is dispatched through the manager's UI
 * dispatcher, while cancellation remains a cheap thread-safe flag checked by the worker.
 */
public final class JobContext {
  private final JobHandle handle;
  private final Consumer<JobProgress> progressReporter;

  JobContext(JobHandle handle, Consumer<JobProgress> progressReporter) {
    this.handle = Objects.requireNonNull(handle, "handle");
    this.progressReporter = Objects.requireNonNull(progressReporter, "progressReporter");
  }

  /** Returns whether the caller should stop at its next safe operation boundary. */
  public boolean isCancellationRequested() {
    return handle.isCancellationRequested();
  }

  /** Throws a control-flow exception when cancellation has been requested. */
  public void checkpoint() throws JobCancelledException {
    if (isCancellationRequested() || Thread.currentThread().isInterrupted()) {
      throw new JobCancelledException();
    }
  }

  /** Checks cancellation and then publishes a validated, non-sensitive progress snapshot. */
  public void reportProgress(JobProgress progress) throws JobCancelledException {
    checkpoint();
    progressReporter.accept(Objects.requireNonNull(progress, "progress"));
  }
}
