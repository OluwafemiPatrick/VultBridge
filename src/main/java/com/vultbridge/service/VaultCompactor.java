package com.vultbridge.service;

import com.vultbridge.platform.CompactionCandidate;
import com.vultbridge.platform.VaultAccessException;
import com.vultbridge.platform.VaultAlreadyOpenException;
import com.vultbridge.vault.AppendCommitProtocol;
import com.vultbridge.vault.CommitCodec;
import com.vultbridge.vault.FixedHeaderCodec;
import com.vultbridge.vault.HeaderSlotAuthenticator;
import com.vultbridge.vault.ManifestCodec;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.RecordCrypto;
import com.vultbridge.vault.RecordId;
import com.vultbridge.vault.RecordIdGenerator;
import com.vultbridge.vault.RecordRef;
import com.vultbridge.vault.RecordRole;
import com.vultbridge.vault.UnverifiedHeaderSlot;
import com.vultbridge.vault.VaultCommit;
import com.vultbridge.vault.VaultDataException;
import com.vultbridge.vault.VaultFormat;
import com.vultbridge.vault.VaultManifest;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;

/**
 * Builds one authenticated compacted candidate from the current source manifest.
 *
 * <p>The source remains open and unchanged. The candidate receives the source immutable wrapped-key
 * envelope, fresh record IDs, freshly encrypted FILE chunks, one new MANIFEST, one new COMMIT, and
 * two initial authenticated slots. Every source FILE chunk is authenticated before it is copied;
 * the candidate is left unpublished for the later force/publication/validation steps.
 */
final class VaultCompactor {
  private static final int MAXIMUM_COMMIT_STABILIZATION_ATTEMPTS = 16;

  private VaultCompactor() {}

  /** Builds and durably installs the candidate's initial committed state without publishing it. */
  static CompactionBuild build(
      VaultSession source,
      CompactionOperation operation,
      CompactionCandidate candidate,
      VaultOperationControl control)
      throws IOException, VaultDataException, JobCancelledException {
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(operation, "operation");
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(control, "control");
    if (!source.vaultPath().equals(operation.sourceVaultPath())) {
      throw new IllegalArgumentException("Compaction source session does not match operation");
    }
    if (!operation.finalOutputPath().isPresent()
        || !operation.candidatePath().isPresent()
        || !operation.candidatePath().orElseThrow().equals(candidate.temporaryPath())) {
      throw new IllegalArgumentException("Compaction candidate paths are incomplete");
    }

    try {
      return candidate.withChannel(channel -> buildOnChannel(source, channel, control));
    } catch (CancellationException exception) {
      throw new JobCancelledException();
    } catch (IOException | VaultDataException | JobCancelledException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new IOException("Compaction writer failed", exception);
    }
  }

  private static CompactionBuild buildOnChannel(
      VaultSession source, FileChannel candidateChannel, VaultOperationControl control)
      throws IOException, VaultDataException, JobCancelledException {
    control.checkpoint();
    writePlaceholderHeader(source, candidateChannel);
    var protocol = AppendCommitProtocol.forCreation(candidateChannel);
    var recordIds = new RecordIdGenerator();
    var compactedEntries = new ArrayList<ManifestEntry>(source.manifest().fileCount());
    long completedBytes = 0;
    long totalBytes = source.manifest().liveLogicalFileBytes();
    control.reportProgress(new JobProgress(JobPhase.PREPARING, 0, source.manifest().fileCount()));

    for (ManifestEntry entry : source.manifest().entries()) {
      control.checkpoint();
      var layout = com.vultbridge.vault.FileRecordLayout.forLogicalSize(entry.logicalSize());
      RecordId destinationId = recordIds.next();
      RecordRef destinationRef =
          protocol.appendFileRecordFromVault(
              destinationId,
              layout,
              source.keys(),
              source.channel(),
              source.keys(),
              entry,
              source.authenticatedCommitEnd(),
              control::isCancellationRequested);
      compactedEntries.add(
          new ManifestEntry(
              entry.displayName(),
              destinationRef,
              entry.logicalSize(),
              layout.chunkCount(),
              Instant.ofEpochMilli(entry.importedAtUtc().toEpochMilli())));
      completedBytes = Math.addExact(completedBytes, entry.logicalSize());
      control.reportProgress(new JobProgress(JobPhase.PROCESSING, completedBytes, totalBytes));
    }

    VaultManifest compactedManifest = new VaultManifest(List.copyOf(compactedEntries));
    RecordRef commitRef = appendManifestAndCommit(source, protocol, recordIds, compactedManifest);
    control.checkpoint();
    protocol.forceAppendedRecords();
    installInitialSlots(source, protocol, commitRef);
    control.reportProgress(
        new JobProgress(
            JobPhase.FINALIZING, source.manifest().fileCount(), source.manifest().fileCount()));
    return new CompactionBuild(compactedManifest);
  }

  /**
   * Forces, publishes, and validates an already-built candidate without removing the source.
   *
   * <p>After the non-overwriting move succeeds, validation is mandatory and is not cancellable:
   * stopping after publication would leave an unverified replacement while the source remains
   * available. A validation failure attempts identity-safe removal of only this published output.
   */
  static VaultSnapshot publishAndValidate(
      VaultSession source,
      CompactionPathPreparer.PreparedCompaction prepared,
      CompactionBuild build,
      VaultOperationControl control)
      throws IOException, VaultOperationException, JobCancelledException {
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(prepared, "prepared");
    Objects.requireNonNull(build, "build");
    Objects.requireNonNull(control, "control");
    control.checkpoint();
    try {
      prepared.candidate().publish();
    } catch (IOException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    }

    VaultSnapshot validated;
    byte[] expectedImmutableHeader = source.immutableHeader();
    try {
      validated =
          VaultUnlocker.validateWithKeys(
              prepared.candidate().finalPath(), source.keys(), expectedImmutableHeader);
      if (!validated.manifest().entries().equals(build.manifest().entries())
          || validated.manifest().liveLogicalFileBytes() != build.manifest().liveLogicalFileBytes()
          || validated.manifest().fileCount() != build.manifest().fileCount()) {
        throw new UnableToUnlockVaultException();
      }
    } catch (VaultAlreadyOpenException exception) {
      cleanupPublished(prepared);
      throw new VaultOperationException(JobFailureCategory.VAULT_ALREADY_OPEN);
    } catch (VaultAccessException exception) {
      cleanupPublished(prepared);
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    } catch (UnableToUnlockVaultException exception) {
      cleanupPublished(prepared);
      throw new VaultOperationException(JobFailureCategory.SECURITY);
    } catch (VaultOperationException exception) {
      cleanupPublished(prepared);
      throw exception;
    } finally {
      Arrays.fill(expectedImmutableHeader, (byte) 0);
    }
    return validated;
  }

  private static void cleanupPublished(CompactionPathPreparer.PreparedCompaction prepared) {
    try {
      prepared.candidate().removePublished();
    } catch (IOException | RuntimeException cleanupFailure) {
      // The source remains authoritative; cleanup is best-effort and never targets by filename
      // pattern.
    }
  }

  private static void writePlaceholderHeader(VaultSession source, FileChannel candidate)
      throws IOException {
    byte[] immutableHeader = source.immutableHeader();
    byte[] zeroRecordId = new byte[VaultFormat.RECORD_ID_BYTES];
    byte[] zeroTag = new byte[VaultFormat.HMAC_SHA256_BYTES];
    var placeholderA = new UnverifiedHeaderSlot(0, 0, zeroRecordId, 0, 0, zeroTag);
    var placeholderB = new UnverifiedHeaderSlot(1, 0, zeroRecordId, 0, 0, zeroTag);
    byte[] encodedCandidateHeader = new byte[VaultFormat.FIXED_HEADER_BYTES];
    byte[] encodedSlotA = FixedHeaderCodec.encodeSlot(placeholderA);
    byte[] encodedSlotB = FixedHeaderCodec.encodeSlot(placeholderB);
    try {
      System.arraycopy(immutableHeader, 0, encodedCandidateHeader, 0, immutableHeader.length);
      System.arraycopy(
          encodedSlotA,
          0,
          encodedCandidateHeader,
          VaultFormat.HEADER_SLOT_A_OFFSET,
          encodedSlotA.length);
      System.arraycopy(
          encodedSlotB,
          0,
          encodedCandidateHeader,
          VaultFormat.HEADER_SLOT_B_OFFSET,
          encodedSlotB.length);
      writeFully(candidate, ByteBuffer.wrap(encodedCandidateHeader), 0);
    } finally {
      Arrays.fill(immutableHeader, (byte) 0);
      Arrays.fill(encodedCandidateHeader, (byte) 0);
      Arrays.fill(encodedSlotA, (byte) 0);
      Arrays.fill(encodedSlotB, (byte) 0);
    }
  }

  private static RecordRef appendManifestAndCommit(
      VaultSession source,
      AppendCommitProtocol protocol,
      RecordIdGenerator recordIds,
      VaultManifest compactedManifest)
      throws IOException {
    RecordId manifestId = recordIds.next();
    byte[] manifestPlaintext = ManifestCodec.encode(compactedManifest);
    byte[] encryptedManifest;
    try {
      encryptedManifest =
          RecordCrypto.encryptSingleBody(
              source.keys(), manifestId, RecordRole.MANIFEST, manifestPlaintext);
    } finally {
      Arrays.fill(manifestPlaintext, (byte) 0);
    }
    RecordRef manifestRef;
    try {
      manifestRef =
          protocol.appendBoundedRecord(manifestId, RecordRole.MANIFEST, encryptedManifest);
    } finally {
      Arrays.fill(encryptedManifest, (byte) 0);
    }

    RecordId commitId = recordIds.next();
    VaultCommit commit = stableCommit(manifestRef, compactedManifest);
    byte[] commitPlaintext = CommitCodec.encode(commit);
    byte[] encryptedCommit;
    try {
      encryptedCommit =
          RecordCrypto.encryptSingleBody(
              source.keys(), commitId, RecordRole.COMMIT, commitPlaintext);
    } finally {
      Arrays.fill(commitPlaintext, (byte) 0);
    }
    RecordRef commitRef;
    try {
      commitRef = protocol.appendBoundedRecord(commitId, RecordRole.COMMIT, encryptedCommit);
    } finally {
      Arrays.fill(encryptedCommit, (byte) 0);
    }
    if (commit.committedEnd() != commitRef.endOffset()) {
      throw new IllegalStateException("Compacted COMMIT length did not stabilize");
    }
    return commitRef;
  }

  private static VaultCommit stableCommit(RecordRef manifestRef, VaultManifest manifest) {
    long commitOffset = manifestRef.endOffset();
    long committedEnd = Math.addExact(commitOffset, VaultFormat.RECORD_FRAME_HEADER_BYTES + 16L);
    for (int attempt = 0; attempt < MAXIMUM_COMMIT_STABILIZATION_ATTEMPTS; attempt++) {
      var candidate =
          new VaultCommit(
              manifestRef, committedEnd, manifest.liveLogicalFileBytes(), manifest.fileCount());
      byte[] encoded = CommitCodec.encode(candidate);
      long encryptedLength;
      try {
        encryptedLength = Math.addExact(encoded.length, VaultFormat.AEAD_TAG_BYTES);
      } finally {
        Arrays.fill(encoded, (byte) 0);
      }
      long nextEnd =
          Math.addExact(
              commitOffset, Math.addExact(VaultFormat.RECORD_FRAME_HEADER_BYTES, encryptedLength));
      if (nextEnd == committedEnd) {
        return candidate;
      }
      committedEnd = nextEnd;
    }
    throw new IllegalStateException("Compacted COMMIT length did not stabilize");
  }

  private static void installInitialSlots(
      VaultSession source, AppendCommitProtocol protocol, RecordRef commitRef) throws IOException {
    byte[] vaultId = source.keys().vaultId();
    try (var headerKey = source.keys().copyHeaderMacKey()) {
      var slotA =
          HeaderSlotAuthenticator.createSlot(
              headerKey,
              vaultId,
              0,
              1,
              commitRef.recordId().bytes(),
              commitRef.offset(),
              commitRef.storedLength());
      var slotB =
          HeaderSlotAuthenticator.createSlot(
              headerKey,
              vaultId,
              1,
              1,
              commitRef.recordId().bytes(),
              commitRef.offset(),
              commitRef.storedLength());
      protocol.installInitialSlots(slotA, slotB);
    }
  }

  private static void writeFully(FileChannel channel, ByteBuffer source, long offset)
      throws IOException {
    long position = offset;
    while (source.hasRemaining()) {
      int written = channel.write(source, position);
      if (written <= 0) {
        throw new IOException("Unable to write fixed candidate header");
      }
      position = Math.addExact(position, written);
    }
  }

  /** Holds the authenticated manifest built into an unpublished candidate. */
  record CompactionBuild(VaultManifest manifest) {
    CompactionBuild {
      Objects.requireNonNull(manifest, "manifest");
    }
  }
}
