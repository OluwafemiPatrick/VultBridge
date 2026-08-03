package com.vultbridge.service;

import java.util.Objects;
import java.util.Optional;

/**
 * Carries the sanitized terminal result of a Compact &amp; Replace service operation.
 *
 * <p>The result contains metadata only. A completed operation may provide the validated compacted
 * vault snapshot; a cancelled or failed operation may provide the still-usable source snapshot.
 * Failure categories are optional because cancellation and successful source removal are not
 * failures. Complete paths, keys, passphrases, plaintext, and raw exception details are excluded.
 */
public record CompactionResult(
    CompactionOutcome outcome,
    Optional<VaultSnapshot> resultingVault,
    Optional<JobFailureCategory> failureCategory) {
  public CompactionResult {
    Objects.requireNonNull(outcome, "outcome");
    Objects.requireNonNull(resultingVault, "resultingVault");
    Objects.requireNonNull(failureCategory, "failureCategory");

    boolean completed =
        outcome == CompactionOutcome.COMPLETED_SOURCE_REMOVED
            || outcome == CompactionOutcome.COMPLETED_SOURCE_RETAINED;
    if (completed != resultingVault.isPresent()) {
      throw new IllegalArgumentException(
          "Completed compaction must have a resulting vault and non-completed work must not");
    }
    boolean failed = outcome == CompactionOutcome.FAILED_SOURCE_RETAINED;
    if (failed != failureCategory.isPresent()) {
      throw new IllegalArgumentException(
          "Only failed compaction may carry an expected failure category");
    }
    if (outcome == CompactionOutcome.CANCELLED_SOURCE_RETAINED && failureCategory.isPresent()) {
      throw new IllegalArgumentException("Cancelled compaction must not carry a failure category");
    }
  }

  /** Creates a successful result after the replacement has validated. */
  public static CompactionResult completed(boolean sourceRemoved, VaultSnapshot compactedVault) {
    return new CompactionResult(
        sourceRemoved
            ? CompactionOutcome.COMPLETED_SOURCE_REMOVED
            : CompactionOutcome.COMPLETED_SOURCE_RETAINED,
        Optional.of(Objects.requireNonNull(compactedVault, "compactedVault")),
        Optional.empty());
  }

  /** Creates a cancellation result that retains the source vault. */
  public static CompactionResult cancelled() {
    return new CompactionResult(
        CompactionOutcome.CANCELLED_SOURCE_RETAINED, Optional.empty(), Optional.empty());
  }

  /** Creates a sanitized pre-removal failure result that retains the source vault. */
  public static CompactionResult failed(JobFailureCategory category) {
    return new CompactionResult(
        CompactionOutcome.FAILED_SOURCE_RETAINED,
        Optional.empty(),
        Optional.of(Objects.requireNonNull(category, "category")));
  }
}
