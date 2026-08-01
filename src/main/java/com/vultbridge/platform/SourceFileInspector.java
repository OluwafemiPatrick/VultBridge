package com.vultbridge.platform;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;

/**
 * Applies the MVP no-follow regular-file policy to one prospective import source.
 *
 * <p>Inspection performs no content read and retains no path. Callers must inspect again after
 * streaming because selection and attributes can change concurrently.
 */
public final class SourceFileInspector {
  private SourceFileInspector() {}

  /**
   * Reads a source's current no-follow attributes.
   *
   * @throws SourceFileRejectedException for a directory, symbolic link, non-regular, or unreadable
   *     path
   * @throws IOException when filesystem metadata cannot be read
   */
  public static SourceFileSnapshot inspect(Path source)
      throws IOException, SourceFileRejectedException {
    Objects.requireNonNull(source, "source");
    BasicFileAttributes attributes =
        Files.readAttributes(source, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (attributes.isSymbolicLink() || !attributes.isRegularFile() || !Files.isReadable(source)) {
      throw new SourceFileRejectedException();
    }
    return new SourceFileSnapshot(
        attributes.size(), attributes.lastModifiedTime().toInstant(), attributes.fileKey());
  }
}
