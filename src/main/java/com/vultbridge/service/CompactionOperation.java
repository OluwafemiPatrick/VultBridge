package com.vultbridge.service;

import com.vultbridge.vault.VaultFormat;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/**
 * Internal metadata contract for one serialized compaction operation.
 *
 * <p>The service owns this value; it is deliberately package-private so exact paths cannot enter
 * JavaFX state. Source and destination identities are carried explicitly, while generated output
 * and candidate paths remain absent until later preparation steps assign them. The authenticated
 * manifest and aggregate totals are copied from one {@link VaultSnapshot} and cross-checked here.
 * This type carries no passphrase, key, manifest bytes, or file content.
 */
record CompactionOperation(
    Path sourceVaultPath,
    Path destinationDirectory,
    Optional<Path> finalOutputPath,
    Optional<Path> candidatePath,
    VaultSnapshot sourceSnapshot,
    long liveLogicalFileBytes,
    int fileCount,
    JobProgress progress) {
  CompactionOperation {
    Objects.requireNonNull(sourceVaultPath, "sourceVaultPath");
    Objects.requireNonNull(destinationDirectory, "destinationDirectory");
    Objects.requireNonNull(finalOutputPath, "finalOutputPath");
    Objects.requireNonNull(candidatePath, "candidatePath");
    Objects.requireNonNull(sourceSnapshot, "sourceSnapshot");
    Objects.requireNonNull(progress, "progress");
    if (liveLogicalFileBytes < 0 || liveLogicalFileBytes > VaultFormat.MAXIMUM_LIVE_FILE_BYTES) {
      throw new IllegalArgumentException("Live file data is outside the v1 limit");
    }
    if (fileCount < 0 || fileCount > VaultFormat.MAXIMUM_FILE_COUNT) {
      throw new IllegalArgumentException("File count is outside the v1 limit");
    }
    if (sourceSnapshot.manifest().liveLogicalFileBytes() != liveLogicalFileBytes
        || sourceSnapshot.manifest().fileCount() != fileCount) {
      throw new IllegalArgumentException("Compaction totals do not match authenticated metadata");
    }
    if (finalOutputPath.isPresent() && candidatePath.isPresent()) {
      Path finalPath = finalOutputPath.orElseThrow();
      Path candidate = candidatePath.orElseThrow();
      if (finalPath.equals(candidate)) {
        throw new IllegalArgumentException("Candidate and final output paths must differ");
      }
    }
  }

  /** Creates the initial service-owned operation before naming and candidate creation. */
  static CompactionOperation initial(
      Path sourceVaultPath, Path destinationDirectory, VaultSnapshot sourceSnapshot) {
    Objects.requireNonNull(sourceSnapshot, "sourceSnapshot");
    return new CompactionOperation(
        Objects.requireNonNull(sourceVaultPath, "sourceVaultPath").toAbsolutePath().normalize(),
        Objects.requireNonNull(destinationDirectory, "destinationDirectory")
            .toAbsolutePath()
            .normalize(),
        Optional.empty(),
        Optional.empty(),
        sourceSnapshot,
        sourceSnapshot.manifest().liveLogicalFileBytes(),
        sourceSnapshot.manifest().fileCount(),
        new JobProgress(JobPhase.PREPARING, 0, sourceSnapshot.manifest().fileCount()));
  }

  /** Returns the same operation after exact output and candidate paths have been assigned. */
  CompactionOperation withPreparedPaths(Path finalPath, Path candidate) {
    return new CompactionOperation(
        sourceVaultPath,
        destinationDirectory,
        Optional.of(Objects.requireNonNull(finalPath, "finalPath").toAbsolutePath().normalize()),
        Optional.of(Objects.requireNonNull(candidate, "candidate").toAbsolutePath().normalize()),
        sourceSnapshot,
        liveLogicalFileBytes,
        fileCount,
        progress);
  }
}
