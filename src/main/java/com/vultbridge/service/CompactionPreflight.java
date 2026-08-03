package com.vultbridge.service;

import com.vultbridge.platform.VaultSidecarLock;
import com.vultbridge.vault.VaultFormat;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;

/**
 * Performs the read-only filesystem and checked-size checks required before compaction writes.
 *
 * <p>The source is checked as the same no-follow regular path retained by the open session. The
 * destination directory is validated before its file-store hint is read. This class does not create
 * a candidate or mutate either path.
 */
final class CompactionPreflight {
  private CompactionPreflight() {}

  /** Reads source/destination metadata and computes a bounded candidate estimate. */
  static CompactionStorageEstimate inspect(CompactionOperation operation) throws IOException {
    Objects.requireNonNull(operation, "operation");
    BasicFileAttributes sourceAttributes =
        Files.readAttributes(
            operation.sourceVaultPath(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!sourceAttributes.isRegularFile() || sourceAttributes.isSymbolicLink()) {
      throw new IOException("Compaction source is unavailable");
    }
    long sourcePhysicalBytes = Files.size(operation.sourceVaultPath());

    BasicFileAttributes destinationAttributes =
        Files.readAttributes(
            operation.destinationDirectory(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!destinationAttributes.isDirectory()
        || destinationAttributes.isSymbolicLink()
        || destinationAttributes.fileKey() == null) {
      throw new IOException("Compaction destination is unavailable");
    }
    var fileStore = Files.getFileStore(operation.destinationDirectory());
    if (!VaultSidecarLock.isSupportedFileStoreType(fileStore.type())) {
      throw new IOException("Compaction filesystem is unsupported");
    }
    long usableBytes = fileStore.getUsableSpace();
    if (usableBytes < 0) {
      throw new IOException("Compaction usable space is unavailable");
    }

    long estimatedCandidateBytes =
        CompactionSizeEstimator.estimate(operation.sourceSnapshot().manifest());
    long safetyMarginBytes = VaultFormat.COMPACTION_SAFETY_MARGIN_BYTES;
    long requiredBytes;
    try {
      requiredBytes = Math.addExact(estimatedCandidateBytes, safetyMarginBytes);
    } catch (ArithmeticException exception) {
      throw new IOException("Compaction size estimate overflow", exception);
    }
    return new CompactionStorageEstimate(
        sourcePhysicalBytes,
        operation.liveLogicalFileBytes(),
        operation.fileCount(),
        estimatedCandidateBytes,
        safetyMarginBytes,
        requiredBytes,
        usableBytes);
  }

  /** Rejects a preflight result that cannot satisfy the estimate and margin. */
  static void requireSufficientSpace(CompactionStorageEstimate estimate) throws IOException {
    Objects.requireNonNull(estimate, "estimate");
    if (!estimate.hasSufficientSpace()) {
      throw new IOException("Compaction destination has insufficient space");
    }
  }
}
