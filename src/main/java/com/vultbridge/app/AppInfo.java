package com.vultbridge.app;

/**
 * Provides public, non-sensitive identity metadata for the desktop application.
 *
 * <p>This class is deliberately limited to values that are safe to display in window titles,
 * diagnostics, and package metadata. It must never contain vault or user-specific information.
 */
public final class AppInfo {
  public static final String NAME = "VultBridge";
  public static final String VERSION = "0.1.0-SNAPSHOT";

  private AppInfo() {}
}
