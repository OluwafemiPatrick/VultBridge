package com.vultbridge.platform;

import java.io.IOException;
import java.nio.channels.FileChannel;
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
 * Owns a create-new temporary plaintext export and its non-overwriting publication lifecycle.
 *
 * <p>The temporary file is created beside the requested destination through an unguessable name and
 * an already-open no-follow channel. Captured APFS file identities let cleanup follow a benign
 * same-parent directory rename without guessing by filename alone. Publication forces and closes
 * the file before moving it without {@code REPLACE_EXISTING}. The object is confined to one
 * background operation.
 */
public final class ExportFileTarget implements AutoCloseable {
  private static final int MAXIMUM_CREATE_ATTEMPTS = 16;

  private final Path destination;
  private final Path originalDirectory;
  private final Path temporaryPath;
  private final Path temporaryName;
  private final Object directoryFileKey;
  private final Object temporaryFileKey;
  private FileChannel channel;
  private boolean published;
  private boolean closed;

  private ExportFileTarget(
      Path destination,
      Path originalDirectory,
      Path temporaryPath,
      Path temporaryName,
      Object directoryFileKey,
      Object temporaryFileKey,
      FileChannel channel) {
    this.destination = destination;
    this.originalDirectory = originalDirectory;
    this.temporaryPath = temporaryPath;
    this.temporaryName = temporaryName;
    this.directoryFileKey = directoryFileKey;
    this.temporaryFileKey = temporaryFileKey;
    this.channel = channel;
  }

  /** Creates a new temporary output beside a destination that must not already exist. */
  public static ExportFileTarget create(Path requestedDestination) throws IOException {
    Objects.requireNonNull(requestedDestination, "requestedDestination");
    Path destination = requestedDestination.toAbsolutePath().normalize();
    Path fileName = destination.getFileName();
    Path directory = destination.getParent();
    if (fileName == null
        || directory == null
        || Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
      throw new java.nio.file.FileAlreadyExistsException("Export destination is unavailable");
    }
    BasicFileAttributes directoryAttributes =
        Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!directoryAttributes.isDirectory() || directoryAttributes.isSymbolicLink()) {
      throw new IOException("Export directory is unavailable");
    }
    Object directoryFileKey = directoryAttributes.fileKey();
    if (directoryFileKey == null) {
      throw new IOException("Export directory identity is unavailable");
    }

    for (int attempt = 0; attempt < MAXIMUM_CREATE_ATTEMPTS; attempt++) {
      Path temporaryName =
          fileName.getFileSystem().getPath(".vultbridge-export-" + UUID.randomUUID() + ".tmp");
      Path temporary = directory.resolve(temporaryName);
      try {
        FileChannel channel =
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
          channel.close();
          throw new IOException("Export temporary identity is unavailable");
        }
        return new ExportFileTarget(
            destination,
            directory,
            temporary,
            temporaryName,
            directoryFileKey,
            temporaryAttributes.fileKey(),
            channel);
      } catch (java.nio.file.FileAlreadyExistsException ignored) {
        // A cryptographically random collision is retried without opening an existing path.
      }
    }
    throw new IOException("Unable to create export temporary file");
  }

  /**
   * Gives one action temporary access to the create-new output channel.
   *
   * <p>The channel remains owned by this target and must not be closed or retained by the action.
   */
  public void write(ChannelAction action) throws IOException {
    Objects.requireNonNull(action, "action");
    if (channel == null || published) {
      throw new IllegalStateException("Export target is no longer writable");
    }
    action.write(channel);
  }

  /** Forces, closes, and publishes the completed output without replacing an existing path. */
  public void publish() throws IOException {
    if (channel == null || published) {
      throw new IllegalStateException("Export target cannot be published");
    }
    channel.force(true);
    channel.close();
    channel = null;
    Files.move(temporaryPath, destination);
    published = true;
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    if (channel != null) {
      try {
        channel.close();
      } catch (IOException ignored) {
        // Cleanup remains best-effort and path-free.
      }
      channel = null;
    }
    if (!published) {
      try {
        removeOwnedTemporary();
      } catch (IOException | SecurityException ignored) {
        // Cleanup is best-effort and failure details may contain a sensitive host path.
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
    // APFS supplies stable file keys. The check prevents benign directory replacement from making
    // cleanup target an unrelated same-named file. A hostile same-user process can still race the
    // following unlink, which is outside the unlocked-host threat model.
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
    // A normal same-parent rename is the common benign race. Search only this bounded directory;
    // recursively searching the host for plaintext would be unsafe and unbounded.
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

  /** Writes to a borrowed export channel without transferring channel ownership. */
  @FunctionalInterface
  public interface ChannelAction {
    /** Performs one bounded streaming write and must not close or retain the supplied channel. */
    void write(FileChannel channel) throws IOException;
  }
}
