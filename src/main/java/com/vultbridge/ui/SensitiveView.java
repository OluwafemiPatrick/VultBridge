package com.vultbridge.ui;

/** Marks a view that owns controls which may briefly contain sensitive user input. */
interface SensitiveView {
  /** Clears all sensitive control values before navigation or application shutdown. */
  void clearSensitiveState();
}
