package com.vultbridge.service;

/**
 * Metadata-only result of compaction storage preflight.
 *
 * <p>The candidate size is calculated from authenticated current manifest metadata and exact v1
 * record framing. The required value includes the fixed policy safety margin; usable space is only
 * a hint and every subsequent write must still handle storage failure. No path, key, or file bytes
 * are retained.
 */
public record CompactionStorageEstimate(
    long sourcePhysicalVaultBytes,
    long liveLogicalFileBytes,
    int fileCount,
    long estimatedCandidateBytes,
    long safetyMarginBytes,
    long requiredDestinationBytes,
    long usableDestinationBytes) {
  public CompactionStorageEstimate {
    if (sourcePhysicalVaultBytes < 0
        || liveLogicalFileBytes < 0
        || estimatedCandidateBytes < 0
        || safetyMarginBytes < 0
        || requiredDestinationBytes < 0
        || usableDestinationBytes < 0) {
      throw new IllegalArgumentException("Storage estimate values must not be negative");
    }
    if (fileCount < 0) {
      throw new IllegalArgumentException("Storage estimate file count must not be negative");
    }
    try {
      if (Math.addExact(estimatedCandidateBytes, safetyMarginBytes) != requiredDestinationBytes) {
        throw new IllegalArgumentException("Required destination bytes are inconsistent");
      }
    } catch (ArithmeticException exception) {
      throw new IllegalArgumentException("Required destination bytes overflow", exception);
    }
  }

  /** Returns whether the latest usable-space hint satisfies the estimate and margin. */
  public boolean hasSufficientSpace() {
    return usableDestinationBytes >= requiredDestinationBytes;
  }
}
