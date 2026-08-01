package com.vultbridge.vault;

import java.util.Objects;

/**
 * Represents authenticated v1 COMMIT plaintext before its cross-record relationships are trusted.
 *
 * <p>The constructor enforces local role and policy bounds. {@link
 * #requireConsistentWith(RecordRef, VaultManifest)} must succeed before a commit can select a
 * manifest or expose metadata.
 */
public record VaultCommit(
    RecordRef manifestRef, long committedEnd, long liveLogicalFileBytes, int fileCount) {
  public VaultCommit {
    Objects.requireNonNull(manifestRef, "manifestRef");
    if (manifestRef.expectedRole() != RecordRole.MANIFEST
        || committedEnd < VaultFormat.FIXED_HEADER_BYTES
        || liveLogicalFileBytes < 0
        || liveLogicalFileBytes > VaultFormat.MAXIMUM_LIVE_FILE_BYTES
        || fileCount < 0
        || fileCount > VaultFormat.MAXIMUM_FILE_COUNT) {
      throw new IllegalArgumentException("Commit fields are outside the v1 range");
    }
  }

  /** Verifies the commit's own final-frame boundary and exact authenticated manifest totals. */
  public void requireConsistentWith(RecordRef commitRef, VaultManifest manifest)
      throws VaultDataException {
    Objects.requireNonNull(commitRef, "commitRef");
    Objects.requireNonNull(manifest, "manifest");
    if (commitRef.expectedRole() != RecordRole.COMMIT
        || committedEnd != commitRef.endOffset()
        || manifestRef.endOffset() > commitRef.offset()
        || liveLogicalFileBytes != manifest.liveLogicalFileBytes()
        || fileCount != manifest.fileCount()) {
      throw new VaultDataException();
    }
    // Entry references become session metadata only after the authenticated COMMIT supplies their
    // upper bound. Checking every reference here prevents a validly encrypted manifest from
    // carrying an impossible seek beyond the committed state into later FILE operations.
    for (ManifestEntry entry : manifest.entries()) {
      entry.fileRef().requireWithin(committedEnd);
    }
  }
}
