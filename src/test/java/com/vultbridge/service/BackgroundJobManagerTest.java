package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class BackgroundJobManagerTest {
  private static final Duration TEST_TIMEOUT = Duration.ofSeconds(3);

  @Test
  void executesOffThreadAndDeliversProgressAndSuccess() throws InterruptedException {
    var completed = new CountDownLatch(1);
    var result = new AtomicReference<String>();
    var workerThread = new AtomicReference<String>();
    var progress = new CopyOnWriteArrayList<JobProgress>();
    try (var manager = new BackgroundJobManager(Runnable::run)) {
      manager.submit(
          context -> {
            workerThread.set(Thread.currentThread().getName());
            context.reportProgress(new JobProgress(JobPhase.PROCESSING, 1, 2));
            context.reportProgress(new JobProgress(JobPhase.FINALIZING, 2, 2));
            return "complete";
          },
          new JobCallbacks<>(
              value -> {
                result.set(value);
                completed.countDown();
              },
              progress::add,
              ignored -> completed.countDown(),
              completed::countDown));

      assertTrue(completed.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
      assertEquals("complete", result.get());
      assertEquals("vultbridge-background-job", workerThread.get());
      assertEquals(
          List.of(
              new JobProgress(JobPhase.PROCESSING, 1, 2),
              new JobProgress(JobPhase.FINALIZING, 2, 2)),
          progress);
      assertFalse(manager.isActive());
    }
  }

  @Test
  void rejectsAConflictingOperation() throws InterruptedException {
    var started = new CountDownLatch(1);
    var release = new CountDownLatch(1);
    var completed = new CountDownLatch(1);
    try (var manager = new BackgroundJobManager(Runnable::run)) {
      manager.submit(
          context -> {
            started.countDown();
            release.await();
            context.checkpoint();
            return "first";
          },
          callbacks(completed));

      assertTrue(started.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
      assertThrows(
          IllegalStateException.class,
          () -> manager.submit(context -> "second", callbacks(new CountDownLatch(1))));
      release.countDown();
      assertTrue(completed.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
    }
  }

  @Test
  void cancelsCooperativelyAtCheckpoint() throws InterruptedException {
    var started = new CountDownLatch(1);
    var cancelled = new CountDownLatch(1);
    try (var manager = new BackgroundJobManager(Runnable::run)) {
      JobHandle handle =
          manager.submit(
              context -> {
                started.countDown();
                while (true) {
                  context.checkpoint();
                  Thread.onSpinWait();
                }
              },
              new JobCallbacks<>(
                  ignored -> {}, ignored -> {}, ignored -> {}, cancelled::countDown));

      assertTrue(started.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
      handle.requestCancellation();

      assertTrue(cancelled.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
      assertTrue(handle.isCancellationRequested());
      assertFalse(manager.isActive());
    }
  }

  @Test
  void reportsOnlySanitizedFailureCategory() throws InterruptedException {
    var completed = new CountDownLatch(1);
    var failure = new AtomicReference<JobFailureCategory>();
    try (var manager = new BackgroundJobManager(Runnable::run)) {
      manager.submit(
          context -> {
            throw new IOException("sensitive path must not reach the callback");
          },
          new JobCallbacks<>(
              ignored -> completed.countDown(),
              ignored -> {},
              category -> {
                failure.set(category);
                completed.countDown();
              },
              completed::countDown));

      assertTrue(completed.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
      assertEquals(JobFailureCategory.FILESYSTEM, failure.get());
    }
  }

  @Test
  void preservesExplicitSanitizedVaultOperationCategory() throws InterruptedException {
    var completed = new CountDownLatch(1);
    var failure = new AtomicReference<JobFailureCategory>();
    try (var manager = new BackgroundJobManager(Runnable::run)) {
      manager.submit(
          context -> {
            throw new VaultOperationException(JobFailureCategory.SECURITY);
          },
          new JobCallbacks<>(
              ignored -> completed.countDown(),
              ignored -> {},
              category -> {
                failure.set(category);
                completed.countDown();
              },
              completed::countDown));

      assertTrue(completed.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
      assertEquals(JobFailureCategory.SECURITY, failure.get());
    }
  }

  @Test
  void sanitizedVaultOperationFailureRetainsNoSensitiveDetail() {
    var failure = new VaultOperationException(JobFailureCategory.FILESYSTEM);

    assertEquals(JobFailureCategory.FILESYSTEM, failure.category());
    assertEquals(null, failure.getMessage());
    assertEquals(null, failure.getCause());
    assertEquals(0, failure.getStackTrace().length);
  }

  @Test
  void closeRequestsCancellationAndRejectsNewWork() throws InterruptedException {
    var started = new CountDownLatch(1);
    var cancelled = new CountDownLatch(1);
    var manager = new BackgroundJobManager(Runnable::run);
    manager.submit(
        context -> {
          started.countDown();
          while (true) {
            context.checkpoint();
            Thread.onSpinWait();
          }
        },
        new JobCallbacks<>(ignored -> {}, ignored -> {}, ignored -> {}, cancelled::countDown));

    assertTrue(started.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
    manager.close(TEST_TIMEOUT);

    assertTrue(cancelled.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
    assertFalse(manager.isActive());
    assertThrows(
        IllegalStateException.class,
        () -> manager.submit(context -> "late", callbacks(new CountDownLatch(1))));
  }

  @Test
  void shutdownCleanupRunsAfterCooperativeWorkerUseEnds() throws InterruptedException {
    var started = new CountDownLatch(1);
    var cleanup = new CountDownLatch(1);
    var sessionInUse = new AtomicBoolean(true);
    var manager = new BackgroundJobManager(Runnable::run);
    manager.submit(
        context -> {
          started.countDown();
          try {
            while (true) {
              context.checkpoint();
              Thread.onSpinWait();
            }
          } finally {
            sessionInUse.set(false);
          }
        },
        new JobCallbacks<>(ignored -> {}, ignored -> {}, ignored -> {}, () -> {}));

    assertTrue(started.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
    manager.close(
        TEST_TIMEOUT,
        () -> {
          assertFalse(sessionInUse.get());
          cleanup.countDown();
        });

    assertTrue(cleanup.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
  }

  @Test
  void timedOutShutdownDefersCleanupAndUsesADaemonWorker() throws InterruptedException {
    var started = new CountDownLatch(1);
    var release = new CountDownLatch(1);
    var cleanup = new CountDownLatch(1);
    var daemon = new AtomicBoolean();
    var manager = new BackgroundJobManager(Runnable::run);
    manager.submit(
        context -> {
          daemon.set(Thread.currentThread().isDaemon());
          started.countDown();
          boolean released = false;
          while (!released) {
            try {
              released = release.await(10, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ignored) {
              // Model an OS/provider call that does not terminate when Java interrupts it.
            }
          }
          return null;
        },
        new JobCallbacks<>(ignored -> {}, ignored -> {}, ignored -> {}, () -> {}));

    assertTrue(started.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
    manager.close(Duration.ZERO, cleanup::countDown);

    assertTrue(daemon.get());
    assertEquals(1, cleanup.getCount());
    release.countDown();
    assertTrue(cleanup.await(TEST_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
  }

  private static JobCallbacks<String> callbacks(CountDownLatch completed) {
    return new JobCallbacks<>(
        ignored -> completed.countDown(),
        ignored -> {},
        ignored -> completed.countDown(),
        completed::countDown);
  }
}
