package com.vultbridge.service;

/** Abstracts delivery of job callbacks onto the UI thread selected by the application. */
@FunctionalInterface
public interface UiDispatcher {
  /** Schedules an action for execution by the UI event loop. */
  void dispatch(Runnable action);
}
