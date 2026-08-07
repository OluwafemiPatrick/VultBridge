package com.vultbridge.service;

/**
 * Describes the terminal source-preservation outcome of one Compact &amp; Replace operation.
 *
 * <p>Expected storage and path failures are represented by {@link JobFailureCategory#FILESYSTEM} or
 * another approved category on {@link CompactionResult}; they are never exposed as raw filesystem
 * exceptions. The source-retained outcomes are intentionally distinct because a validated
 * replacement and a failed or cancelled operation have different user-visible results.
 */
public enum CompactionOutcome {
  /** The replacement validated and an approved identity-safe remover removed the exact source. */
  COMPLETED_SOURCE_REMOVED,

  /** The replacement validated but the source was retained by policy or removal failure. */
  COMPLETED_SOURCE_RETAINED,

  /** The operation was cancelled before source removal. */
  CANCELLED_SOURCE_RETAINED,

  /** The operation failed before source removal. */
  FAILED_SOURCE_RETAINED
}
