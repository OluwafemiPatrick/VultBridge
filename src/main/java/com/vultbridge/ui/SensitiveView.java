package com.vultbridge.ui;

/** A view that owns controls which may briefly contain sensitive user input. */
interface SensitiveView {
  void clearSensitiveState();
}
