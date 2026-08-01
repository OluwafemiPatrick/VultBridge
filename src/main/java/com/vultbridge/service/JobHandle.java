package com.vultbridge.service;

/** Handle for requesting cooperative cancellation of one active operation. */
public interface JobHandle {
  void requestCancellation();

  boolean isCancellationRequested();
}
