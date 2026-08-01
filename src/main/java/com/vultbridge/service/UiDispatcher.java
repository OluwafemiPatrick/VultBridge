package com.vultbridge.service;

/** Delivers job notifications onto the UI thread selected by the application. */
@FunctionalInterface
public interface UiDispatcher {
  void dispatch(Runnable action);
}
