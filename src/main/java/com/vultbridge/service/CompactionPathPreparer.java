package com.vultbridge.service;

import com.vultbridge.platform.CompactionCandidate;
import com.vultbridge.platform.VaultSidecarLock;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.Objects;
import java.util.function.IntSupplier;

/**
 * Validates a selected compaction directory, chooses a collision-resistant final name, and owns
 * creation of the no-follow temporary candidate.
 *
 * <p>This boundary performs only path preparation and empty-candidate creation. It does not write a
 * vault header or record, publish a candidate, or remove a source vault. The caller must retain and
 * close the returned candidate for every outcome.
 */
final class CompactionPathPreparer {
  private static final int MAXIMUM_FINAL_NAME_ATTEMPTS = 16;

  private CompactionPathPreparer() {}

  /**
   * Prepares one owned candidate and updates the operation with its exact output paths.
   *
   * @throws IOException when the selected directory is unavailable or no collision-free name can be
   *     prepared
   */
  static PreparedCompaction prepare(
      CompactionOperation operation, Instant timestamp, IntSupplier randomSuffixSource)
      throws IOException {
    Objects.requireNonNull(operation, "operation");
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(randomSuffixSource, "randomSuffixSource");
    Path directory = operation.destinationDirectory();
    validateDestinationDirectory(directory);

    for (int attempt = 0; attempt < MAXIMUM_FINAL_NAME_ATTEMPTS; attempt++) {
      String outputName =
          CompactionNameGenerator.generate(
              operation.sourceSnapshot().vaultDisplayName(), timestamp, randomSuffixSource);
      Path finalPath = directory.resolve(outputName).toAbsolutePath().normalize();
      if (finalPath.equals(operation.sourceVaultPath())) {
        continue;
      }
      try {
        CompactionCandidate candidate = CompactionCandidate.create(finalPath);
        return new PreparedCompaction(
            operation.withPreparedPaths(finalPath, candidate.temporaryPath()), candidate);
      } catch (java.nio.file.FileAlreadyExistsException collision) {
        // A final-name collision is retried with a new secure-random suffix; no existing path was
        // opened.
      }
    }
    throw new IOException("Unable to choose a compaction output name");
  }

  /** Selects a collision-free output name without creating a candidate or touching the source. */
  static String chooseOutputName(
      CompactionOperation operation, Instant timestamp, IntSupplier randomSuffixSource)
      throws IOException {
    Objects.requireNonNull(operation, "operation");
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(randomSuffixSource, "randomSuffixSource");
    validateDestinationDirectory(operation.destinationDirectory());
    for (int attempt = 0; attempt < MAXIMUM_FINAL_NAME_ATTEMPTS; attempt++) {
      String outputName =
          CompactionNameGenerator.generate(
              operation.sourceSnapshot().vaultDisplayName(), timestamp, randomSuffixSource);
      Path finalPath =
          operation.destinationDirectory().resolve(outputName).toAbsolutePath().normalize();
      if (!finalPath.equals(operation.sourceVaultPath())
          && !Files.exists(finalPath, LinkOption.NOFOLLOW_LINKS)) {
        return outputName;
      }
    }
    throw new IOException("Unable to choose a compaction output name");
  }

  /** Prepares the exact name already displayed in a confirmation dialog. */
  static PreparedCompaction prepare(CompactionOperation operation, String outputFileName)
      throws IOException {
    Objects.requireNonNull(operation, "operation");
    Objects.requireNonNull(outputFileName, "outputFileName");
    if (outputFileName.isBlank()
        || outputFileName.contains("/")
        || outputFileName.contains("\\")
        || !outputFileName.endsWith(".vltb")) {
      throw new IOException("Compaction output name is invalid");
    }
    if (!CompactionNameGenerator.isGeneratedFor(
        operation.sourceSnapshot().vaultDisplayName(), outputFileName)) {
      throw new IOException("Compaction output name is invalid");
    }
    validateDestinationDirectory(operation.destinationDirectory());
    Path finalPath =
        operation.destinationDirectory().resolve(outputFileName).toAbsolutePath().normalize();
    if (finalPath.equals(operation.sourceVaultPath())) {
      throw new IOException("Compaction output matches its source");
    }
    CompactionCandidate candidate = CompactionCandidate.create(finalPath);
    return new PreparedCompaction(
        operation.withPreparedPaths(finalPath, candidate.temporaryPath()), candidate);
  }

  private static void validateDestinationDirectory(Path directory) throws IOException {
    BasicFileAttributes directoryAttributes =
        Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!directoryAttributes.isDirectory()
        || directoryAttributes.isSymbolicLink()
        || directoryAttributes.fileKey() == null) {
      throw new IOException("Compaction directory is unavailable");
    }
    if (!VaultSidecarLock.isSupportedFileStoreType(Files.getFileStore(directory).type())) {
      throw new IOException("Compaction filesystem is unsupported");
    }
  }

  /** Holds the immutable prepared operation and the candidate resource that must be closed. */
  record PreparedCompaction(CompactionOperation operation, CompactionCandidate candidate)
      implements AutoCloseable {
    PreparedCompaction {
      Objects.requireNonNull(operation, "operation");
      Objects.requireNonNull(candidate, "candidate");
      if (!operation.finalOutputPath().orElseThrow().equals(candidate.finalPath())
          || !operation.candidatePath().orElseThrow().equals(candidate.temporaryPath())) {
        throw new IllegalArgumentException("Prepared operation paths do not match its candidate");
      }
    }

    @Override
    public void close() {
      candidate.close();
    }
  }
}
