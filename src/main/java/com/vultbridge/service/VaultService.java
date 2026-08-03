package com.vultbridge.service;

import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.platform.VaultAccessException;
import com.vultbridge.platform.VaultAlreadyOpenException;
import com.vultbridge.vault.VaultDataException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

/**
 * Owns the application's sole unlocked vault session behind a metadata-only service boundary.
 *
 * <p>JavaFX callers receive {@link VaultSnapshot} values and never receive channels, keys, or the
 * session itself. All methods are confined to the application-owned serialized background worker,
 * except idempotent {@link #close()} after that worker has stopped.
 */
public final class VaultService implements AutoCloseable {
  private final SecureRandom compactionRandom = new SecureRandom();
  private final CompactionSourceRemover sourceRemover;
  private VaultSession session;

  /** Creates a service using normal filesystem deletion for validated source removal. */
  public VaultService() {
    this(Files::delete);
  }

  VaultService(CompactionSourceRemover sourceRemover) {
    this.sourceRemover = Objects.requireNonNull(sourceRemover, "sourceRemover");
  }

  /** Creates and retains a new unlocked vault session. */
  public VaultSnapshot create(Path path, SensitiveBytes passphrase) throws VaultOperationException {
    requireClosed();
    try {
      VaultSession created = VaultCreator.create(path, passphrase);
      return retain(created);
    } catch (VaultAlreadyOpenException exception) {
      throw new VaultOperationException(JobFailureCategory.VAULT_ALREADY_OPEN);
    } catch (VaultAccessException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    } catch (UnableToUnlockVaultException exception) {
      throw new VaultOperationException(JobFailureCategory.UNABLE_TO_UNLOCK);
    }
  }

  /** Opens and retains an existing authenticated vault session. */
  public VaultSnapshot open(Path path, SensitiveBytes passphrase) throws VaultOperationException {
    requireClosed();
    try {
      VaultSession opened = VaultUnlocker.open(path, passphrase);
      return retain(opened);
    } catch (VaultAlreadyOpenException exception) {
      throw new VaultOperationException(JobFailureCategory.VAULT_ALREADY_OPEN);
    } catch (VaultAccessException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    } catch (UnableToUnlockVaultException exception) {
      throw new VaultOperationException(JobFailureCategory.UNABLE_TO_UNLOCK);
    }
  }

  /** Imports selected regular files sequentially into the current session. */
  public VaultSnapshot importFiles(List<Path> sources, VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    try {
      return VaultImporter.importFiles(requireOpen(), sources, control);
    } catch (VaultOperationException exception) {
      closeInvalidatedSession(exception);
      throw exception;
    }
  }

  /** Logically deletes one selected authenticated display name. */
  public VaultSnapshot delete(String selectedDisplayName, VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    try {
      return VaultDeleter.delete(requireOpen(), selectedDisplayName, control);
    } catch (VaultOperationException exception) {
      closeInvalidatedSession(exception);
      throw exception;
    }
  }

  /** Authentically exports one selected entry and returns unchanged current metadata. */
  public VaultSnapshot export(
      String selectedDisplayName, Path destination, VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    VaultSession current = requireOpen();
    VaultExporter.export(current, selectedDisplayName, destination, control);
    return current.snapshot();
  }

  /**
   * Captures the service-owned metadata boundary for a future compaction operation.
   *
   * <p>This method performs no candidate creation or vault mutation. It is package-private so the
   * JavaFX layer cannot retain exact paths or an operation context; the eventual compaction job
   * will be submitted through the application-owned background worker.
   */
  CompactionOperation prepareCompaction(Path destinationDirectory) throws VaultOperationException {
    Objects.requireNonNull(destinationDirectory, "destinationDirectory");
    try {
      VaultSession current = requireOpen();
      return CompactionOperation.initial(
          current.vaultPath(), destinationDirectory, current.snapshot());
    } catch (VaultOperationException exception) {
      closeInvalidatedSession(exception);
      throw exception;
    }
  }

  /**
   * Performs read-only compaction preflight and selects the exact output name shown for
   * confirmation.
   *
   * <p>No candidate is created and no vault state is mutated. The selected name is used by the
   * confirmed overload of {@link #compact(Path, CompactionPreview, VaultOperationControl)} so the
   * UI never confirms one output name while the service silently writes another.
   */
  public CompactionPreview previewCompaction(Path destinationDirectory)
      throws VaultOperationException {
    CompactionOperation operation = prepareCompaction(destinationDirectory);
    try {
      CompactionStorageEstimate estimate = CompactionPreflight.inspect(operation);
      CompactionPreflight.requireSufficientSpace(estimate);
      String outputName =
          CompactionPathPreparer.chooseOutputName(
              operation, java.time.Instant.now(), () -> compactionRandom.nextInt(0x0100_0000));
      return CompactionPreview.create(
          operation.sourceSnapshot().vaultDisplayName(), outputName, estimate);
    } catch (IOException | RuntimeException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    }
  }

  /** Performs read-only compaction storage preflight without creating a candidate. */
  CompactionStorageEstimate preflightCompaction(Path destinationDirectory)
      throws VaultOperationException {
    return previewCompaction(destinationDirectory).estimate();
  }

  /**
   * Compacts the current vault into a validated timestamped replacement and removes the exact
   * source path only after validation succeeds.
   *
   * <p>The operation is intended to run through the application-owned background worker. It owns no
   * passphrase input, retains only the service session, and returns metadata-only terminal results.
   * Cancellation and failures before source removal leave the source session usable.
   */
  public CompactionResult compact(Path destinationDirectory, VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    return compactInternal(destinationDirectory, null, control);
  }

  /**
   * Runs a confirmed compaction using the exact output name shown by {@link #previewCompaction}.
   */
  public CompactionResult compact(
      Path destinationDirectory, CompactionPreview preview, VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    Objects.requireNonNull(preview);
    return compactInternal(destinationDirectory, preview.outputFileName(), control);
  }

  private CompactionResult compactInternal(
      Path destinationDirectory, String confirmedOutputName, VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    Objects.requireNonNull(destinationDirectory, "destinationDirectory");
    Objects.requireNonNull(control, "control");
    VaultSession source = requireOpen();
    try {
      CompactionOperation operation =
          CompactionOperation.initial(source.vaultPath(), destinationDirectory, source.snapshot());
      CompactionStorageEstimate estimate = CompactionPreflight.inspect(operation);
      CompactionPreflight.requireSufficientSpace(estimate);
      try (var prepared =
          confirmedOutputName == null
              ? CompactionPathPreparer.prepare(
                  operation, java.time.Instant.now(), () -> compactionRandom.nextInt(0x0100_0000))
              : CompactionPathPreparer.prepare(operation, confirmedOutputName)) {
        VaultCompactor.CompactionBuild build =
            VaultCompactor.build(source, prepared.operation(), prepared.candidate(), control);
        VaultSnapshot validated =
            VaultCompactor.publishAndValidate(source, prepared, build, control);
        return installReplacementSession(source, prepared.candidate().finalPath(), validated);
      }
    } catch (JobCancelledException exception) {
      throw exception;
    } catch (VaultOperationException exception) {
      closeInvalidatedSession(exception);
      throw exception;
    } catch (VaultDataException exception) {
      throw new VaultOperationException(JobFailureCategory.SECURITY);
    } catch (IOException | RuntimeException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    }
  }

  /** Returns current authenticated metadata after a preceding operation's terminal boundary. */
  public VaultSnapshot snapshot() throws VaultOperationException {
    try {
      return requireOpen().snapshot();
    } catch (VaultOperationException exception) {
      close();
      throw exception;
    }
  }

  /** Locks the current vault by dropping metadata, wiping keys, and releasing owned resources. */
  public void lock() {
    VaultSession current = requireOpen();
    session = null;
    current.close();
  }

  /** Returns whether this service currently owns an unlocked session. */
  public boolean isOpen() {
    return session != null && !session.isClosed();
  }

  @Override
  public void close() {
    if (session != null) {
      session.close();
      session = null;
    }
  }

  private VaultSnapshot retain(VaultSession candidate) throws VaultOperationException {
    Objects.requireNonNull(candidate, "candidate");
    boolean retained = false;
    try {
      VaultSnapshot snapshot = candidate.snapshot();
      session = candidate;
      retained = true;
      return snapshot;
    } finally {
      if (!retained) {
        candidate.close();
      }
    }
  }

  private void closeInvalidatedSession(VaultOperationException failure) {
    if (failure.sessionInvalidated()) {
      close();
    }
  }

  private CompactionResult installReplacementSession(
      VaultSession source, Path compactedPath, VaultSnapshot validated)
      throws VaultOperationException {
    byte[] expectedImmutableHeader = source.immutableHeader();
    com.vultbridge.crypto.VaultKeySet transferredKeys = source.detachKeysForReplacement();
    VaultSession replacement;
    try {
      replacement =
          VaultUnlocker.openWithKeys(compactedPath, transferredKeys, expectedImmutableHeader);
    } catch (VaultAlreadyOpenException exception) {
      source.close();
      session = null;
      throw new VaultOperationException(JobFailureCategory.VAULT_ALREADY_OPEN);
    } catch (VaultAccessException exception) {
      source.close();
      session = null;
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    } catch (UnableToUnlockVaultException exception) {
      source.close();
      session = null;
      throw new VaultOperationException(JobFailureCategory.SECURITY);
    } finally {
      java.util.Arrays.fill(expectedImmutableHeader, (byte) 0);
    }

    Path sourcePath = source.vaultPath();
    boolean sourceIdentityMatches = source.sourceIdentityMatches();
    boolean sourceRemoved = false;
    try {
      // Release the source channel and sidecar lock before the normal unlink. Java has no portable
      // conditional-unlink primitive, so the identity check plus deletion is deliberately not
      // described as atomic or secure erasure; preserving data is preferred if identity is lost.
      source.close();
      if (sourceIdentityMatches) {
        try {
          sourceRemover.remove(sourcePath);
          sourceRemoved = true;
        } catch (IOException | SecurityException ignored) {
          // A validated replacement is still successful when source removal cannot complete.
        }
      }
    } finally {
      session = replacement;
    }
    return CompactionResult.completed(sourceRemoved, validated);
  }

  private void requireClosed() {
    if (isOpen()) {
      throw new IllegalStateException("A vault session is already open");
    }
  }

  private VaultSession requireOpen() {
    if (!isOpen()) {
      throw new IllegalStateException("No vault session is open");
    }
    return session;
  }
}
