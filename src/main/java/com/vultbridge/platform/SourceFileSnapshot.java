package com.vultbridge.platform;

import java.time.Instant;
import java.util.Objects;

/**
 * Captures the no-follow attributes needed to detect import-source mutation.
 *
 * <p>The snapshot contains no source path or content. A file key is retained only when the
 * filesystem supplies one, and comparison always includes size and modification time.
 */
public record SourceFileSnapshot(long size, Instant modifiedTime, Object fileKey) {
  public SourceFileSnapshot {
    if (size < 0) {
      throw new IllegalArgumentException("Source size must not be negative");
    }
    Objects.requireNonNull(modifiedTime, "modifiedTime");
  }

  /** Returns whether a later snapshot still describes the same detectable source state. */
  public boolean matches(SourceFileSnapshot later) {
    Objects.requireNonNull(later, "later");
    if (size != later.size || !modifiedTime.equals(later.modifiedTime)) {
      return false;
    }
    // When either observation supplies identity, both must supply the same identity. Treating a
    // disappearing key as unchanged would discard detectable evidence of replacement.
    return (fileKey == null && later.fileKey == null)
        || (fileKey != null && fileKey.equals(later.fileKey));
  }
}
