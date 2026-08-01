package com.vultbridge.service;

/** A bounded-memory operation executed away from the JavaFX application thread. */
@FunctionalInterface
public interface BackgroundJob<T> {
  T execute(JobContext context) throws Exception;
}
