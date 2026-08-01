package com.vultbridge.service;

import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Runs at most one cooperative I/O or cryptographic job at a time on a bounded executor. */
public final class BackgroundJobManager implements AutoCloseable {
  private static final Duration DEFAULT_SHUTDOWN_TIMEOUT = Duration.ofSeconds(5);

  private final Object lifecycleLock = new Object();
  private final UiDispatcher uiDispatcher;
  private final ThreadPoolExecutor executor;
  private JobControl activeJob;
  private boolean closed;

  public BackgroundJobManager(UiDispatcher uiDispatcher) {
    this.uiDispatcher = Objects.requireNonNull(uiDispatcher, "uiDispatcher");
    executor =
        new ThreadPoolExecutor(
            1,
            1,
            0,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(1),
            runnable -> {
              var thread = new Thread(runnable, "vultbridge-background-job");
              thread.setDaemon(false);
              return thread;
            },
            new ThreadPoolExecutor.AbortPolicy());
  }

  public <T> JobHandle submit(BackgroundJob<T> job, JobCallbacks<T> callbacks) {
    Objects.requireNonNull(job, "job");
    Objects.requireNonNull(callbacks, "callbacks");

    var control = new JobControl();
    synchronized (lifecycleLock) {
      if (closed) {
        throw new IllegalStateException("Background job manager is closed");
      }
      if (activeJob != null) {
        throw new IllegalStateException("Another background operation is already active");
      }
      activeJob = control;
      try {
        executor.execute(() -> executeJob(control, job, callbacks));
      } catch (RejectedExecutionException exception) {
        activeJob = null;
        throw new IllegalStateException("Background operation could not be scheduled", exception);
      }
    }
    return control;
  }

  public boolean isActive() {
    synchronized (lifecycleLock) {
      return activeJob != null;
    }
  }

  public void requestCancellation() {
    synchronized (lifecycleLock) {
      if (activeJob != null) {
        activeJob.requestCancellation();
      }
    }
  }

  @Override
  public void close() {
    close(DEFAULT_SHUTDOWN_TIMEOUT);
  }

  public void close(Duration timeout) {
    Objects.requireNonNull(timeout, "timeout");
    if (timeout.isNegative()) {
      throw new IllegalArgumentException("Shutdown timeout must not be negative");
    }

    synchronized (lifecycleLock) {
      if (closed) {
        return;
      }
      closed = true;
      if (activeJob != null) {
        activeJob.requestCancellation();
      }
      executor.shutdown();
    }

    try {
      if (!executor.awaitTermination(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
        executor.shutdownNow();
        executor.awaitTermination(timeout.toMillis(), TimeUnit.MILLISECONDS);
      }
    } catch (InterruptedException exception) {
      executor.shutdownNow();
      Thread.currentThread().interrupt();
    }
  }

  private <T> void executeJob(JobControl control, BackgroundJob<T> job, JobCallbacks<T> callbacks) {
    Runnable completion;
    var context =
        new JobContext(
            control,
            progress -> uiDispatcher.dispatch(() -> callbacks.progressed().accept(progress)));
    try {
      context.checkpoint();
      T result = job.execute(context);
      context.checkpoint();
      completion = () -> callbacks.succeeded().accept(result);
    } catch (JobCancelledException exception) {
      completion = callbacks.cancelled();
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      completion = callbacks.cancelled();
    } catch (Exception exception) {
      JobFailureCategory category = categorize(exception);
      completion = () -> callbacks.failed().accept(category);
    } catch (Error error) {
      finish(control);
      throw error;
    }

    finish(control);
    uiDispatcher.dispatch(completion);
  }

  private void finish(JobControl control) {
    synchronized (lifecycleLock) {
      if (activeJob == control) {
        activeJob = null;
      }
      control.markFinished();
    }
  }

  private static JobFailureCategory categorize(Exception exception) {
    if (exception instanceof IllegalArgumentException) {
      return JobFailureCategory.INPUT_REJECTED;
    }
    if (exception instanceof IOException) {
      return JobFailureCategory.FILESYSTEM;
    }
    if (exception instanceof SecurityException) {
      return JobFailureCategory.SECURITY;
    }
    return JobFailureCategory.INTERNAL;
  }

  private static final class JobControl implements JobHandle {
    private final AtomicBoolean cancellationRequested = new AtomicBoolean();
    private final AtomicBoolean finished = new AtomicBoolean();

    @Override
    public void requestCancellation() {
      if (!finished.get()) {
        cancellationRequested.set(true);
      }
    }

    @Override
    public boolean isCancellationRequested() {
      return cancellationRequested.get();
    }

    private void markFinished() {
      finished.set(true);
    }
  }
}
