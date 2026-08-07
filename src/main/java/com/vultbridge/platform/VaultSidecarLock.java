package com.vultbridge.platform;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Owns the exclusive same-directory sidecar lock for one vault session.
 *
 * <p>Acquisition opens {@code <vault filename>.lock} without following links, validates a regular
 * local lock file, and retains both channel and {@link FileLock} until close. Closing is idempotent
 * and deliberately does not delete the sidecar path, avoiding a race in which another process has
 * already acquired the persistent lock file.
 */
public final class VaultSidecarLock implements AutoCloseable {
  private static final Set<String> SUPPORTED_FILESTORE_TYPES = Set.of("apfs", "ext4");

  private final FileChannel channel;
  private final FileLock lock;
  private boolean closed;

  private VaultSidecarLock(FileChannel channel, FileLock lock) {
    this.channel = channel;
    this.lock = lock;
  }

  /**
   * Acquires the vault's exclusive sidecar lock or reports contention/access failure without paths.
   */
  public static VaultSidecarLock acquire(Path vaultPath)
      throws VaultAlreadyOpenException, VaultAccessException {
    Objects.requireNonNull(vaultPath, "vaultPath");
    Path fileName = vaultPath.getFileName();
    Path parent = vaultPath.toAbsolutePath().getParent();
    if (fileName == null || parent == null) {
      throw new VaultAccessException();
    }
    Path lockPath = parent.resolve(fileName + ".lock");
    FileChannel channel = null;
    FileLock acquired = null;
    try {
      requireSupportedFileStore(parent);
      if (Files.isSymbolicLink(lockPath)) {
        throw new VaultAccessException();
      }
      Set<OpenOption> options =
          Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
      channel = FileChannel.open(lockPath, options);
      BasicFileAttributes attributes =
          Files.readAttributes(lockPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!attributes.isRegularFile()) {
        throw new VaultAccessException();
      }
      try {
        acquired = channel.tryLock();
      } catch (OverlappingFileLockException exception) {
        throw new VaultAlreadyOpenException();
      }
      if (acquired == null) {
        throw new VaultAlreadyOpenException();
      }
      return new VaultSidecarLock(channel, acquired);
    } catch (VaultAlreadyOpenException | VaultAccessException exception) {
      closeQuietly(acquired, channel);
      throw exception;
    } catch (IOException | UnsupportedOperationException | SecurityException exception) {
      closeQuietly(acquired, channel);
      throw new VaultAccessException();
    }
  }

  /** Returns whether this owner still retains an open valid lock. */
  public boolean isOpen() {
    return !closed && channel.isOpen() && lock.isValid();
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    closeQuietly(lock, channel);
  }

  private static void requireSupportedFileStore(Path parent)
      throws IOException, VaultAccessException {
    FileStore store = Files.getFileStore(parent);
    if (!isSupportedFileStoreType(store.type())) {
      throw new VaultAccessException();
    }
  }

  /** Returns whether a filesystem type is in the exact currently verified local-storage matrix. */
  public static boolean isSupportedFileStoreType(String type) {
    return type != null && SUPPORTED_FILESTORE_TYPES.contains(type.toLowerCase(Locale.ROOT));
  }

  private static void closeQuietly(FileLock lock, FileChannel channel) {
    if (lock != null) {
      try {
        lock.close();
      } catch (IOException ignored) {
        // Cleanup is best-effort after acquisition failure or during idempotent session shutdown.
      }
    }
    if (channel != null) {
      try {
        channel.close();
      } catch (IOException ignored) {
        // The user-facing boundary remains sanitized and never includes raw filesystem details.
      }
    }
  }
}
