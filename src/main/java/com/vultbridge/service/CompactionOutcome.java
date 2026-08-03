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
  /** The replacement validated and the exact source file was removed. */
  COMPLETED_SOURCE_REMOVED,

  /** The replacement validated but removal of the exact source file failed. */
  COMPLETED_SOURCE_RETAINED,

  /** The operation was cancelled before source removal. */
  CANCELLED_SOURCE_RETAINED,

  /** The operation failed before source removal. */
  FAILED_SOURCE_RETAINED
}
