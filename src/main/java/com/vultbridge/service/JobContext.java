package com.vultbridge.service;

import java.util.Objects;
import java.util.function.Consumer;

/** Cooperative cancellation and progress boundary supplied to a background job. */
public final class JobContext {
  private final JobHandle handle;
  private final Consumer<JobProgress> progressReporter;

  JobContext(JobHandle handle, Consumer<JobProgress> progressReporter) {
    this.handle = Objects.requireNonNull(handle, "handle");
    this.progressReporter = Objects.requireNonNull(progressReporter, "progressReporter");
  }

  public boolean isCancellationRequested() {
    return handle.isCancellationRequested();
  }

  public void checkpoint() throws JobCancelledException {
    if (isCancellationRequested() || Thread.currentThread().isInterrupted()) {
      throw new JobCancelledException();
    }
  }

  public void reportProgress(JobProgress progress) throws JobCancelledException {
    checkpoint();
    progressReporter.accept(Objects.requireNonNull(progress, "progress"));
  }
}
