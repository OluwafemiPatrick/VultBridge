package com.vultbridge.service;

/** Internal control-flow signal raised only at a cooperative job boundary. */
public final class JobCancelledException extends Exception {
  private static final long serialVersionUID = 1L;

  JobCancelledException() {
    super("Background operation cancelled");
  }
}
