package com.vultbridge.platform;

/**
 * Reports that an import source is not an acceptable readable regular file.
 *
 * <p>The exception deliberately contains no source name, path, or underlying filesystem detail.
 */
public final class SourceFileRejectedException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Creates one sanitized source-policy rejection. */
  public SourceFileRejectedException() {
    super(null, null, false, false);
  }
}
