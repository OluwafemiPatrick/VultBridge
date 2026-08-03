package com.vultbridge.platform;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Owns one encrypted compaction candidate and its non-overwriting publication lifecycle.
 *
 * <p>The candidate is created beside an exact final destination with create-new/no-follow
 * semantics. The object retains the open channel and APFS file identities needed to clean only the
 * candidate created by this operation, including after a benign same-parent directory rename. It
 * contains no passphrase, key, plaintext, or vault-format logic and is confined to one serialized
 * background operation.
 */
public final class CompactionCandidate implements AutoCloseable {
  private static final int MAXIMUM_CREATE_ATTEMPTS = 16;

  private final Path finalPath;
  private final Path originalDirectory;
  private final Path temporaryName;
  private final Object directoryFileKey;
  private final Object temporaryFileKey;
  private Path temporaryPath;
  private FileChannel channel;
  private boolean published;
  private boolean removed;
  private boolean closed;

  private CompactionCandidate(
      Path finalPath,
      Path originalDirectory,
      Path temporaryPath,
      Path temporaryName,
      Object directoryFileKey,
      Object temporaryFileKey,
      FileChannel channel) {
    this.finalPath = finalPath;
    this.originalDirectory = originalDirectory;
    this.temporaryPath = temporaryPath;
    this.temporaryName = temporaryName;
    this.directoryFileKey = directoryFileKey;
    this.temporaryFileKey = temporaryFileKey;
    this.channel = channel;
  }

  /**
   * Creates a new encrypted candidate for a final path that must not already exist.
   *
   * @throws FileAlreadyExistsException when the final path is occupied
   * @throws IOException when the destination directory or candidate cannot be safely opened
   */
  public static CompactionCandidate create(Path requestedFinalPath) throws IOException {
    Objects.requireNonNull(requestedFinalPath, "requestedFinalPath");
    Path finalPath = requestedFinalPath.toAbsolutePath().normalize();
    Path fileName = finalPath.getFileName();
    Path directory = finalPath.getParent();
    if (fileName == null || directory == null) {
      throw new IOException("Compaction destination is unavailable");
    }
    if (Files.exists(finalPath, LinkOption.NOFOLLOW_LINKS)) {
      throw new FileAlreadyExistsException("Compaction destination is unavailable");
    }

    BasicFileAttributes directoryAttributes =
        Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!directoryAttributes.isDirectory()
        || directoryAttributes.isSymbolicLink()
        || directoryAttributes.fileKey() == null) {
      throw new IOException("Compaction directory is unavailable");
    }

    for (int attempt = 0; attempt < MAXIMUM_CREATE_ATTEMPTS; attempt++) {
      Path temporaryName =
          fileName.getFileSystem().getPath(".vultbridge-compaction-" + UUID.randomUUID() + ".tmp");
      Path temporary = directory.resolve(temporaryName);
      FileChannel candidateChannel = null;
      try {
        candidateChannel =
            FileChannel.open(
                temporary,
                Set.of(
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ,
                    StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        BasicFileAttributes temporaryAttributes =
            Files.readAttributes(temporary, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!temporaryAttributes.isRegularFile() || temporaryAttributes.fileKey() == null) {
          throw new IOException("Compaction candidate identity is unavailable");
        }
        return new CompactionCandidate(
            finalPath,
            directory,
            temporary,
            temporaryName,
            directoryAttributes.fileKey(),
            temporaryAttributes.fileKey(),
            candidateChannel);
      } catch (FileAlreadyExistsException ignored) {
        closeQuietly(candidateChannel);
      } catch (IOException | RuntimeException exception) {
        closeQuietly(candidateChannel);
        throw exception;
      }
    }
    throw new IOException("Unable to create compaction candidate");
  }

  /** Returns the exact final path this candidate may publish to. */
  public Path finalPath() {
    return finalPath;
  }

  /** Returns the temporary candidate path, which is not a committed v1 vault. */
  public Path temporaryPath() {
    return temporaryPath;
  }

  /** Gives one action temporary access to the owned candidate channel. */
  public void write(ChannelAction action) throws IOException {
    Objects.requireNonNull(action, "action");
    if (channel == null || published || closed) {
      throw new IllegalStateException("Compaction candidate is no longer writable");
    }
    action.write(channel);
  }

  /**
   * Runs one serialized writer action with temporary channel access without transferring ownership.
   */
  public <T> T withChannel(ChannelFunction<T> action) throws Exception {
    Objects.requireNonNull(action, "action");
    if (channel == null || published || closed) {
      throw new IllegalStateException("Compaction candidate channel is unavailable");
    }
    return action.apply(channel);
  }

  /** Forces, closes, and publishes the candidate without replacing an existing final path. */
  public void publish() throws IOException {
    if (channel == null || published || closed) {
      throw new IllegalStateException("Compaction candidate cannot be published");
    }
    channel.force(true);
    channel.close();
    channel = null;
    Files.move(temporaryPath, finalPath);
    published = true;
  }

  /** Removes the exact published inode if validation fails before source removal. */
  public void removePublished() throws IOException {
    if (!published || removed || temporaryPath == null) {
      throw new IllegalStateException("Published compaction output is unavailable");
    }
    Path currentDirectory = locateOriginalDirectory();
    if (currentDirectory == null) {
      return;
    }
    Path candidate = currentDirectory.resolve(finalPath.getFileName());
    try (VaultSidecarLock lock = VaultSidecarLock.acquire(candidate)) {
      if (!lock.isOpen()) {
        return;
      }
      BasicFileAttributes attributes;
      try {
        attributes =
            Files.readAttributes(candidate, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      } catch (java.nio.file.NoSuchFileException missing) {
        removed = true;
        return;
      }
      if (attributes.isRegularFile() && temporaryFileKey.equals(attributes.fileKey())) {
        Files.delete(candidate);
        removed = true;
      }
    } catch (VaultAlreadyOpenException | VaultAccessException ignored) {
      // Never unlink a published vault when its sidecar lock is unavailable or held elsewhere.
    }
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    closeQuietly(channel);
    channel = null;
    if (!published && !removed && temporaryPath != null) {
      try {
        removeOwnedTemporary();
      } catch (IOException | SecurityException ignored) {
        // Cleanup is best-effort and raw path details must not cross the service boundary.
      }
    }
  }

  private void removeOwnedTemporary() throws IOException {
    Path currentDirectory = locateOriginalDirectory();
    if (currentDirectory == null) {
      return;
    }
    Path candidate = currentDirectory.resolve(temporaryName);
    BasicFileAttributes attributes;
    try {
      attributes =
          Files.readAttributes(candidate, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    } catch (java.nio.file.NoSuchFileException ignored) {
      return;
    }
    if (attributes.isRegularFile() && temporaryFileKey.equals(attributes.fileKey())) {
      Files.delete(candidate);
    }
  }

  private Path locateOriginalDirectory() throws IOException {
    if (hasFileKey(originalDirectory, directoryFileKey)) {
      return originalDirectory;
    }
    Path parent = originalDirectory.getParent();
    if (parent == null) {
      return null;
    }
    try (var children = Files.newDirectoryStream(parent)) {
      for (Path child : children) {
        if (hasFileKey(child, directoryFileKey)) {
          return child;
        }
      }
    }
    return null;
  }

  private static boolean hasFileKey(Path path, Object expectedFileKey) {
    try {
      BasicFileAttributes attributes =
          Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      return attributes.isDirectory() && expectedFileKey.equals(attributes.fileKey());
    } catch (IOException | SecurityException ignored) {
      return false;
    }
  }

  private static void closeQuietly(FileChannel candidateChannel) {
    if (candidateChannel != null) {
      try {
        candidateChannel.close();
      } catch (IOException ignored) {
        // Cleanup is best-effort and path-free.
      }
    }
  }

  /** Writes to a borrowed candidate channel without transferring channel ownership. */
  @FunctionalInterface
  public interface ChannelAction {
    /** Performs one bounded write and must not close or retain the supplied channel. */
    void write(FileChannel channel) throws IOException;
  }

  /** Computes one serialized writer result without retaining or closing the supplied channel. */
  @FunctionalInterface
  public interface ChannelFunction<T> {
    /** Applies one bounded writer operation to the borrowed channel. */
    T apply(FileChannel channel) throws Exception;
  }
}
