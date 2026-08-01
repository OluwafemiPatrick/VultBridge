package com.vultbridge.service;

/**
 * Describes a bounded-memory operation that executes away from the JavaFX application thread.
 *
 * <p>Implementations should periodically call {@link JobContext#checkpoint()} and must not include
 * secrets, file names, or full paths in progress or failure reporting.
 */
@FunctionalInterface
public interface BackgroundJob<T> {
  /** Executes the operation and returns the value delivered to its success callback. */
  T execute(JobContext context) throws Exception;
}
