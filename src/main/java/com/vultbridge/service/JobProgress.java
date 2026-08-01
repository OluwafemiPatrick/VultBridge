package com.vultbridge.service;

import java.util.Objects;

/**
 * Immutable, non-sensitive progress snapshot for one background operation.
 *
 * <p>Units are operation-defined but must be internally consistent. The constructor rejects
 * negative values and completed work beyond the declared total.
 */
public record JobProgress(JobPhase phase, long completedUnits, long totalUnits) {
  public JobProgress {
    Objects.requireNonNull(phase, "phase");
    if (completedUnits < 0 || totalUnits < 0 || completedUnits > totalUnits) {
      throw new IllegalArgumentException("Progress units are outside the valid range");
    }
  }

  /** Returns progress normalized to the inclusive range {@code 0.0..1.0}. */
  public double fractionComplete() {
    return totalUnits == 0 ? 0 : (double) completedUnits / totalUnits;
  }
}
