package com.vultbridge.service;

import com.vultbridge.vault.AppendCommitProtocol;
import com.vultbridge.vault.AuthenticatedHeaderSlot;
import com.vultbridge.vault.CommitCodec;
import com.vultbridge.vault.HeaderSlotAuthenticator;
import com.vultbridge.vault.ManifestCodec;
import com.vultbridge.vault.RecordCrypto;
import com.vultbridge.vault.RecordId;
import com.vultbridge.vault.RecordRef;
import com.vultbridge.vault.RecordRole;
import com.vultbridge.vault.VaultCommit;
import com.vultbridge.vault.VaultFormat;
import com.vultbridge.vault.VaultManifest;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Completes one import or delete with the shared authenticated mutation sequence.
 *
 * <p>The caller may have already appended an unreachable FILE record through the supplied protocol.
 * This writer appends the replacement MANIFEST and final COMMIT, forces all appended bytes, then
 * installs and forces exactly the next inactive authenticated slot. Session metadata advances only
 * after that final durability point. No plaintext file content or host path enters this class.
 */
final class VaultMutationWriter {
  private VaultMutationWriter() {}

  /** Completes and installs one new manifest state, returning UI-safe authenticated metadata. */
  static VaultSnapshot commit(
      VaultSession session,
      AppendCommitProtocol protocol,
      VaultManifest nextManifest,
      VaultOperationControl control)
      throws IOException, JobCancelledException, VaultOperationException {
    Objects.requireNonNull(session, "session");
    Objects.requireNonNull(protocol, "protocol");
    Objects.requireNonNull(nextManifest, "nextManifest");
    Objects.requireNonNull(control, "control");
    AuthenticatedHeaderSlot activeSlot = session.activeSlot();
    if (activeSlot.generation() == -1L) {
      throw new IllegalStateException("Header-slot generation is exhausted");
    }

    control.checkpoint();
    RecordId manifestId = session.recordIds().next();
    byte[] manifestPlaintext = ManifestCodec.encode(nextManifest);
    byte[] encryptedManifest;
    try {
      encryptedManifest =
          RecordCrypto.encryptSingleBody(
              session.keys(), manifestId, RecordRole.MANIFEST, manifestPlaintext);
    } finally {
      Arrays.fill(manifestPlaintext, (byte) 0);
    }
    RecordRef manifestRef =
        protocol.appendBoundedRecord(manifestId, RecordRole.MANIFEST, encryptedManifest);

    RecordId commitId = session.recordIds().next();
    VaultCommit commit = stableCommit(manifestRef, manifestRef.endOffset(), nextManifest);
    byte[] commitPlaintext = CommitCodec.encode(commit);
    byte[] encryptedCommit;
    try {
      encryptedCommit =
          RecordCrypto.encryptSingleBody(
              session.keys(), commitId, RecordRole.COMMIT, commitPlaintext);
    } finally {
      Arrays.fill(commitPlaintext, (byte) 0);
    }
    RecordRef commitRef =
        protocol.appendBoundedRecord(commitId, RecordRole.COMMIT, encryptedCommit);
    if (commit.committedEnd() != commitRef.endOffset()) {
      throw new IllegalStateException("COMMIT length did not stabilize");
    }

    // Cancellation remains safe before and after the record force because the old slot still
    // selects the preceding state. Once slot installation begins, cancellation is no longer
    // observed; a failed final force invalidates the session because disk selection is uncertain.
    control.checkpoint();
    protocol.forceAppendedRecords();
    control.checkpoint();

    int nextIndex = 1 - activeSlot.slotIndex();
    long nextGeneration = activeSlot.generation() + 1;
    byte[] vaultId = session.keys().vaultId();
    try (var headerKey = session.keys().copyHeaderMacKey()) {
      var slot =
          HeaderSlotAuthenticator.createSlot(
              headerKey,
              vaultId,
              nextIndex,
              nextGeneration,
              commitId.bytes(),
              commitRef.offset(),
              commitRef.storedLength());
      try {
        protocol.installInactiveSlot(slot);
      } catch (IOException exception) {
        if (protocol.hasUnforcedSlotWrite()) {
          throw VaultOperationException.invalidatedSession(JobFailureCategory.FILESYSTEM);
        }
        throw exception;
      }
      AuthenticatedHeaderSlot authenticated =
          HeaderSlotAuthenticator.verifySlot(slot, vaultId, headerKey).orElseThrow();
      session.installCommittedState(nextManifest, authenticated);
    }
    return new VaultSnapshot(session.vaultDisplayName(), nextManifest, session.channel().size());
  }

  private static VaultCommit stableCommit(
      RecordRef manifestRef, long commitOffset, VaultManifest manifest) {
    long committedEnd =
        Math.addExact(
            commitOffset,
            Math.addExact(VaultFormat.RECORD_FRAME_HEADER_BYTES, VaultFormat.AEAD_TAG_BYTES));
    for (int attempt = 0; attempt < 16; attempt++) {
      var candidate =
          new VaultCommit(
              manifestRef, committedEnd, manifest.liveLogicalFileBytes(), manifest.fileCount());
      byte[] encoded = CommitCodec.encode(candidate);
      int encryptedLength;
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
    throw new IllegalStateException("COMMIT length did not stabilize");
  }
}
