package com.vultbridge.service;

import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs cooperative I/O or cryptographic jobs on one lifecycle-owned background worker.
 *
 * <p>The manager admits only one active operation, uses a bounded executor, and marshals progress
 * and terminal callbacks through a {@link UiDispatcher}. Jobs are cancelled cooperatively during
 * normal use; shutdown adds an interrupt fallback after a bounded wait.
 *
 * <p>This class deliberately converts exceptions to {@link JobFailureCategory} values instead of
 * exposing raw messages that might contain sensitive paths or provider details.
 */
public final class BackgroundJobManager implements AutoCloseable {
  private static final Duration DEFAULT_SHUTDOWN_TIMEOUT = Duration.ofSeconds(5);

  private final Object lifecycleLock = new Object();
  private final UiDispatcher uiDispatcher;
  private final ThreadPoolExecutor executor;
  private JobControl activeJob;
  private boolean closed;

  /** Creates a manager whose notifications are delivered by the supplied UI dispatcher. */
  public BackgroundJobManager(UiDispatcher uiDispatcher) {
    this.uiDispatcher = Objects.requireNonNull(uiDispatcher, "uiDispatcher");
    // A single worker serializes vault mutation. The bounded queue prevents unbounded retention
    // even if the one-active-job admission check and executor state change concurrently.
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

  /**
   * Submits one job and returns its cancellation handle.
   *
   * @throws IllegalStateException if the manager is closed or another operation is active
   */
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

  /** Returns whether a submitted operation has not yet selected its terminal callback. */
  public boolean isActive() {
    synchronized (lifecycleLock) {
      return activeJob != null;
    }
  }

  /** Requests cooperative cancellation of the active operation, if one exists. */
  public void requestCancellation() {
    synchronized (lifecycleLock) {
      if (activeJob != null) {
        activeJob.requestCancellation();
      }
    }
  }

  // Closes the manager using the default bounded shutdown timeout.
  @Override
  public void close() {
    close(DEFAULT_SHUTDOWN_TIMEOUT);
  }

  /**
   * Rejects future submissions, requests cancellation, and waits for worker termination.
   *
   * <p>If cooperative shutdown exceeds {@code timeout}, the worker is interrupted and receives one
   * final bounded wait. The method is idempotent.
   */
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

    // Wait outside lifecycleLock so the worker can acquire it while recording completion.
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
    // Check both before and after user job code so a late cancellation cannot report success.
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

    // Release the admission gate before dispatching user callback code, allowing callbacks to start
    // a subsequent operation without racing the completed job.
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
    // Keep this mapping intentionally coarse; exception messages never cross into the UI layer.
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
