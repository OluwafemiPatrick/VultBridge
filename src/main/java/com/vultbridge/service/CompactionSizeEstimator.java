package com.vultbridge.service;

import com.vultbridge.vault.CommitCodec;
import com.vultbridge.vault.FileRecordLayout;
import com.vultbridge.vault.ManifestCodec;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.RecordId;
import com.vultbridge.vault.RecordRef;
import com.vultbridge.vault.RecordRole;
import com.vultbridge.vault.VaultCommit;
import com.vultbridge.vault.VaultFormat;
import com.vultbridge.vault.VaultManifest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Computes the exact v1 byte size of a compacted candidate from authenticated manifest metadata.
 *
 * <p>The estimator mirrors the writer's fixed header, FILE, MANIFEST, and COMMIT framing. It uses
 * placeholder record IDs because v1 record IDs have a fixed encoded width; offsets and lengths are
 * calculated with checked arithmetic, and temporary codec buffers are wiped after sizing.
 */
final class CompactionSizeEstimator {
  private static final int MAXIMUM_COMMIT_STABILIZATION_ATTEMPTS = 16;

  private CompactionSizeEstimator() {}

  /** Returns the exact candidate byte count before the separate preflight safety margin. */
  static long estimate(VaultManifest manifest) {
    Objects.requireNonNull(manifest, "manifest");
    RecordId placeholderId = new RecordId(new byte[VaultFormat.RECORD_ID_BYTES]);
    var compactedEntries = new ArrayList<ManifestEntry>(manifest.fileCount());
    long nextOffset = VaultFormat.FIXED_HEADER_BYTES;

    for (ManifestEntry entry : manifest.entries()) {
      FileRecordLayout layout = FileRecordLayout.forLogicalSize(entry.logicalSize());
      RecordRef fileRef =
          new RecordRef(placeholderId, nextOffset, layout.storedLength(), RecordRole.FILE);
      compactedEntries.add(
          new ManifestEntry(
              entry.displayName(),
              fileRef,
              entry.logicalSize(),
              layout.chunkCount(),
              entry.importedAtUtc()));
      nextOffset = frameEnd(nextOffset, layout.storedLength());
    }

    VaultManifest compactedManifest = new VaultManifest(List.copyOf(compactedEntries));
    byte[] manifestPlaintext = ManifestCodec.encode(compactedManifest);
    try {
      long manifestStoredLength =
          Math.addExact(manifestPlaintext.length, VaultFormat.AEAD_TAG_BYTES);
      RecordRef manifestRef =
          new RecordRef(placeholderId, nextOffset, manifestStoredLength, RecordRole.MANIFEST);
      long commitOffset = manifestRef.endOffset();
      long committedEnd = Math.addExact(commitOffset, VaultFormat.RECORD_FRAME_HEADER_BYTES + 16L);

      for (int attempt = 0; attempt < MAXIMUM_COMMIT_STABILIZATION_ATTEMPTS; attempt++) {
        VaultCommit commit =
            new VaultCommit(
                manifestRef, committedEnd, manifest.liveLogicalFileBytes(), manifest.fileCount());
        byte[] commitPlaintext = CommitCodec.encode(commit);
        long commitStoredLength;
        try {
          commitStoredLength = Math.addExact(commitPlaintext.length, VaultFormat.AEAD_TAG_BYTES);
        } finally {
          Arrays.fill(commitPlaintext, (byte) 0);
        }
        long nextCommittedEnd = frameEnd(commitOffset, commitStoredLength);
        if (nextCommittedEnd == committedEnd) {
          return nextCommittedEnd;
        }
        committedEnd = nextCommittedEnd;
      }
      throw new IllegalStateException("Compaction COMMIT length did not stabilize");
    } finally {
      Arrays.fill(manifestPlaintext, (byte) 0);
    }
  }

  private static long frameEnd(long offset, long storedLength) {
    return Math.addExact(
        Math.addExact(offset, VaultFormat.RECORD_FRAME_HEADER_BYTES), storedLength);
  }
}
