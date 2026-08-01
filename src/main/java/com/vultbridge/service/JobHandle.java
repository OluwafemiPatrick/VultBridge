package com.vultbridge.service;

/** Exposes cooperative cancellation state for one submitted background operation. */
public interface JobHandle {
  /** Requests cancellation; the job stops when it next reaches a cancellation checkpoint. */
  void requestCancellation();

  /** Returns whether cancellation has been requested for this job. */
  boolean isCancellationRequested();
}
