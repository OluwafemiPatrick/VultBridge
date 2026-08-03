package com.vultbridge.service;

import java.util.Objects;

/**
 * Metadata-only result shown before a user confirms Compact &amp; Replace.
 *
 * <p>The output name is selected by the service after the destination has been validated. The
 * preview contains no path, key, passphrase, manifest bytes, or file content; the service retains
 * the exact source identity and revalidates the destination when the confirmed job starts.
 */
public final class CompactionPreview {
  private final String outputFileName;
  private final CompactionStorageEstimate estimate;

  private CompactionPreview(String outputFileName, CompactionStorageEstimate estimate) {
    this.outputFileName = outputFileName;
    this.estimate = estimate;
  }

  static CompactionPreview create(
      String sourceVaultDisplayName, String outputFileName, CompactionStorageEstimate estimate) {
    Objects.requireNonNull(sourceVaultDisplayName, "sourceVaultDisplayName");
    Objects.requireNonNull(outputFileName, "outputFileName");
    Objects.requireNonNull(estimate, "estimate");
    if (!CompactionNameGenerator.isGeneratedFor(sourceVaultDisplayName, outputFileName)) {
      throw new IllegalArgumentException("Compaction output name is invalid");
    }
    return new CompactionPreview(outputFileName, estimate);
  }

  /** Returns the exact generated filename displayed for confirmation. */
  public String outputFileName() {
    return outputFileName;
  }

  /** Returns the metadata-only storage estimate displayed for confirmation. */
  public CompactionStorageEstimate estimate() {
    return estimate;
  }
}
