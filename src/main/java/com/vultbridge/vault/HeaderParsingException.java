package com.vultbridge.vault;

/**
 * Reports a structurally invalid fixed header through one non-sensitive failure contract.
 *
 * <p>The exception deliberately omits field values and low-level causes so callers cannot surface
 * attacker-controlled bytes or misleading authentication detail.
 */
public final class HeaderParsingException extends Exception {
  private static final long serialVersionUID = 1L;

  HeaderParsingException() {
    super("Invalid VultBridge header");
  }
}
