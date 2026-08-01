package com.vultbridge.service;

import java.util.Objects;

/** Bounded, non-sensitive progress information for a background operation. */
public record JobProgress(JobPhase phase, long completedUnits, long totalUnits) {
  public JobProgress {
    Objects.requireNonNull(phase, "phase");
    if (completedUnits < 0 || totalUnits < 0 || completedUnits > totalUnits) {
      throw new IllegalArgumentException("Progress units are outside the valid range");
    }
  }

  public double fractionComplete() {
    return totalUnits == 0 ? 0 : (double) completedUnits / totalUnits;
  }
}
