package com.vultbridge.ui;

import java.util.Locale;

/** Formats non-negative byte counts for compact UI labels. */
public final class ByteSizeFormatter {
  private static final long KIBIBYTE = 1024;
  private static final long MEBIBYTE = KIBIBYTE * 1024;
  private static final long GIBIBYTE = MEBIBYTE * 1024;

  private ByteSizeFormatter() {}

  public static String format(long bytes) {
    if (bytes < 0) {
      throw new IllegalArgumentException("Byte count must not be negative");
    }
    if (bytes < KIBIBYTE) {
      return bytes + " B";
    }
    if (bytes < MEBIBYTE) {
      return formatUnit(bytes, KIBIBYTE, "KiB");
    }
    if (bytes < GIBIBYTE) {
      return formatUnit(bytes, MEBIBYTE, "MiB");
    }
    return formatUnit(bytes, GIBIBYTE, "GiB");
  }

  private static String formatUnit(long bytes, long unit, String suffix) {
    double value = (double) bytes / unit;
    return String.format(Locale.ROOT, value >= 10 ? "%.0f %s" : "%.1f %s", value, suffix);
  }
}
