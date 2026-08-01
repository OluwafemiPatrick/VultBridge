package com.vultbridge.service;

import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.platform.VaultAccessException;
import com.vultbridge.platform.VaultAlreadyOpenException;
import java.nio.file.Path;
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
  private VaultSession session;

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
