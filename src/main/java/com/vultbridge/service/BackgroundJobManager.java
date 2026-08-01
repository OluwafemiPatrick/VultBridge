package com.vultbridge.service;

import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CancellationException;
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
  private Runnable shutdownCleanup;
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
              // A provider or removed device can make a Java I/O call ignore interruption. A
              // daemon worker prevents that platform failure from keeping the process alive; the
              // serialized shutdown cleanup still runs if the call eventually returns.
              thread.setDaemon(true);
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
    close(DEFAULT_SHUTDOWN_TIMEOUT, () -> {});
  }

  /**
   * Rejects future submissions, requests cancellation, and waits for worker termination.
   *
   * <p>If cooperative shutdown exceeds {@code timeout}, the worker is interrupted and receives one
   * final bounded wait. The method is idempotent.
   */
  public void close(Duration timeout) {
    close(timeout, () -> {});
  }

  /**
   * Closes the manager and runs sensitive-resource cleanup only after active worker use ends.
   *
   * <p>If no operation is active, cleanup runs on the caller before this method returns. Otherwise
   * it runs on the worker's terminal path, including after an interrupt fallback. This ordering
   * prevents callers from closing channels, keys, or locks concurrently with vault work. Cleanup
   * must be idempotent, non-blocking, and safe to call without exposing exception details.
   */
  public void close(Duration timeout, Runnable cleanup) {
    Objects.requireNonNull(timeout, "timeout");
    Objects.requireNonNull(cleanup, "cleanup");
    if (timeout.isNegative()) {
      throw new IllegalArgumentException("Shutdown timeout must not be negative");
    }

    Runnable immediateCleanup = null;
    synchronized (lifecycleLock) {
      if (closed) {
        return;
      }
      closed = true;
      shutdownCleanup = cleanup;
      if (activeJob != null) {
        activeJob.requestCancellation();
      } else {
        immediateCleanup = takeShutdownCleanup();
      }
      executor.shutdown();
    }
    runCleanup(immediateCleanup);

    // Wait outside lifecycleLock so the worker can acquire it while recording completion.
    try {
      if (!executor.awaitTermination(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
        finishNeverStartedJob(executor.shutdownNow());
        executor.awaitTermination(timeout.toMillis(), TimeUnit.MILLISECONDS);
      }
    } catch (InterruptedException exception) {
      finishNeverStartedJob(executor.shutdownNow());
      Thread.currentThread().interrupt();
    }
  }

  private void finishNeverStartedJob(java.util.List<Runnable> abandonedTasks) {
    if (abandonedTasks.isEmpty()) {
      return;
    }
    JobControl abandoned;
    synchronized (lifecycleLock) {
      abandoned = activeJob;
    }
    if (abandoned != null) {
      // shutdownNow returns queued work that can no longer reach executeJob's terminal path. Since
      // the sole task never used vault resources, the close caller may safely complete ownership.
      finish(abandoned);
    }
  }

  private <T> void executeJob(JobControl control, BackgroundJob<T> job, JobCallbacks<T> callbacks) {
    Runnable completion;
    var context =
        new JobContext(
            control,
            progress -> uiDispatcher.dispatch(() -> callbacks.progressed().accept(progress)));
    // The manager checks admission-time cancellation. Each operation owns later checkpoints because
    // only it knows whether cancellation is still safe; an unconditional post-job check could
    // falsely report cancellation after a mutation's authenticated slot was durably installed.
    try {
      context.checkpoint();
      T result = job.execute(context);
      completion = () -> callbacks.succeeded().accept(result);
    } catch (JobCancelledException | CancellationException exception) {
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
    Runnable cleanup = null;
    synchronized (lifecycleLock) {
      if (activeJob == control) {
        activeJob = null;
      }
      control.markFinished();
      if (closed) {
        cleanup = takeShutdownCleanup();
      }
    }
    // Cleanup is intentionally outside the lock and before the terminal UI callback. A late
    // create/open result therefore cannot retain a session beyond application shutdown.
    runCleanup(cleanup);
  }

  private Runnable takeShutdownCleanup() {
    Runnable cleanup = shutdownCleanup;
    shutdownCleanup = null;
    return cleanup;
  }

  private static void runCleanup(Runnable cleanup) {
    if (cleanup != null) {
      cleanup.run();
    }
  }

  private static JobFailureCategory categorize(Exception exception) {
    // Keep this mapping intentionally coarse; exception messages never cross into the UI layer.
    if (exception instanceof VaultOperationException operationException) {
      return operationException.category();
    }
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
