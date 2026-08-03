package com.vultbridge.service;

import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.crypto.V1KeyHierarchy;
import com.vultbridge.platform.VaultAccessException;
import com.vultbridge.platform.VaultAlreadyOpenException;
import com.vultbridge.platform.VaultSidecarLock;
import com.vultbridge.vault.AppendCommitProtocol;
import com.vultbridge.vault.CommitCodec;
import com.vultbridge.vault.FixedHeaderCodec;
import com.vultbridge.vault.HeaderSlotAuthenticator;
import com.vultbridge.vault.ManifestCodec;
import com.vultbridge.vault.RecordCrypto;
import com.vultbridge.vault.RecordId;
import com.vultbridge.vault.RecordIdGenerator;
import com.vultbridge.vault.RecordRef;
import com.vultbridge.vault.RecordRole;
import com.vultbridge.vault.UnverifiedFixedHeader;
import com.vultbridge.vault.UnverifiedHeaderSlot;
import com.vultbridge.vault.VaultCommit;
import com.vultbridge.vault.VaultFormat;
import com.vultbridge.vault.VaultManifest;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Objects;

/**
 * Creates a durable empty v1 vault and returns it through the standard authenticated unlock path.
 *
 * <p>Creation rejects existing and symbolic destinations, acquires the sidecar lock before creating
 * the vault, writes an unauthenticated placeholder header, appends and forces the empty MANIFEST
 * and first COMMIT, installs and forces both authenticated initial slots, then revalidates every
 * layer before returning a session. A failed creation releases all resources but deliberately
 * leaves any incomplete file in place because Java cannot atomically unlink a pathname only if it
 * still identifies the inode created by this operation.
 */
public final class VaultCreator {
  private VaultCreator() {}

  /** Creates a new empty vault without consuming or closing the caller-owned passphrase. */
  public static VaultSession create(Path vaultPath, SensitiveBytes passphrase)
      throws VaultAlreadyOpenException, VaultAccessException, UnableToUnlockVaultException {
    Objects.requireNonNull(vaultPath, "vaultPath");
    Objects.requireNonNull(passphrase, "passphrase");
    String vaultDisplayName = VaultPathPolicy.requireV1VaultFile(vaultPath);
    if (Files.exists(vaultPath, LinkOption.NOFOLLOW_LINKS)) {
      throw new VaultAccessException();
    }

    VaultSidecarLock sidecar = VaultSidecarLock.acquire(vaultPath);
    FileChannel channel = null;
    boolean transferred = false;
    try {
      if (Files.exists(vaultPath, LinkOption.NOFOLLOW_LINKS)) {
        throw new VaultAccessException();
      }
      channel =
          FileChannel.open(
              vaultPath,
              StandardOpenOption.CREATE_NEW,
              StandardOpenOption.READ,
              StandardOpenOption.WRITE,
              LinkOption.NOFOLLOW_LINKS);
      BasicFileAttributes attributes =
          Files.readAttributes(vaultPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (attributes.fileKey() == null) {
        throw new IOException("Vault file identity is unavailable");
      }
      writeInitialState(channel, passphrase);
      VaultSession session =
          VaultUnlocker.openHeld(
              channel, sidecar, passphrase, vaultDisplayName, vaultPath, attributes.fileKey());
      transferred = true;
      return session;
    } catch (IOException | RuntimeException exception) {
      throw new VaultAccessException();
    } finally {
      if (!transferred) {
        closeQuietly(channel);
        sidecar.close();
      }
    }
  }

  private static void writeInitialState(FileChannel channel, SensitiveBytes passphrase)
      throws IOException {
    var recordIds = new RecordIdGenerator();
    try (var createdKeys = V1KeyHierarchy.create(passphrase)) {
      RecordId manifestId = recordIds.next();
      byte[] manifestPlaintext = ManifestCodec.encode(new VaultManifest(List.of()));
      byte[] encryptedManifest;
      try {
        encryptedManifest =
            RecordCrypto.encryptSingleBody(
                createdKeys.keys(), manifestId, RecordRole.MANIFEST, manifestPlaintext);
      } finally {
        java.util.Arrays.fill(manifestPlaintext, (byte) 0);
      }
      var manifestRef =
          new RecordRef(
              manifestId,
              VaultFormat.FIXED_HEADER_BYTES,
              encryptedManifest.length,
              RecordRole.MANIFEST);

      RecordId commitId = recordIds.next();
      long commitOffset = manifestRef.endOffset();
      VaultCommit commit = stableInitialCommit(manifestRef, commitOffset);
      byte[] commitPlaintext = CommitCodec.encode(commit);
      byte[] encryptedCommit;
      try {
        encryptedCommit =
            RecordCrypto.encryptSingleBody(
                createdKeys.keys(), commitId, RecordRole.COMMIT, commitPlaintext);
      } finally {
        java.util.Arrays.fill(commitPlaintext, (byte) 0);
      }
      var commitRef =
          new RecordRef(commitId, commitOffset, encryptedCommit.length, RecordRole.COMMIT);
      if (commit.committedEnd() != commitRef.endOffset()) {
        throw new IllegalStateException("Initial COMMIT length did not stabilize");
      }

      UnverifiedHeaderSlot placeholderA = placeholder(0, commitRef);
      UnverifiedHeaderSlot placeholderB = placeholder(1, commitRef);
      byte[] header =
          FixedHeaderCodec.encode(
              new UnverifiedFixedHeader(
                  createdKeys.wrappedMasterKey(), placeholderA, placeholderB));
      writeFully(channel, ByteBuffer.wrap(header), 0);

      var protocol = AppendCommitProtocol.forCreation(channel);
      RecordRef writtenManifest =
          protocol.appendBoundedRecord(manifestId, RecordRole.MANIFEST, encryptedManifest);
      RecordRef writtenCommit =
          protocol.appendBoundedRecord(commitId, RecordRole.COMMIT, encryptedCommit);
      if (!writtenManifest.equals(manifestRef) || !writtenCommit.equals(commitRef)) {
        throw new IllegalStateException("Initial record offsets diverged");
      }
      protocol.forceAppendedRecords();

      byte[] vaultId = createdKeys.wrappedMasterKey().vaultId();
      try (var headerKey = createdKeys.keys().copyHeaderMacKey()) {
        var slotA =
            HeaderSlotAuthenticator.createSlot(
                headerKey,
                vaultId,
                0,
                1,
                commitId.bytes(),
                commitRef.offset(),
                commitRef.storedLength());
        var slotB =
            HeaderSlotAuthenticator.createSlot(
                headerKey,
                vaultId,
                1,
                1,
                commitId.bytes(),
                commitRef.offset(),
                commitRef.storedLength());
        protocol.installInitialSlots(slotA, slotB);
      }
    }
  }

  private static VaultCommit stableInitialCommit(RecordRef manifestRef, long commitOffset) {
    long committedEnd = commitOffset + VaultFormat.RECORD_FRAME_HEADER_BYTES + 16L;
    for (int attempt = 0; attempt < 16; attempt++) {
      var candidate = new VaultCommit(manifestRef, committedEnd, 0, 0);
      byte[] encoded = CommitCodec.encode(candidate);
      int encryptedLength;
      try {
        encryptedLength = Math.addExact(encoded.length, VaultFormat.AEAD_TAG_BYTES);
      } finally {
        java.util.Arrays.fill(encoded, (byte) 0);
      }
      long nextEnd =
          Math.addExact(
              Math.addExact(commitOffset, VaultFormat.RECORD_FRAME_HEADER_BYTES), encryptedLength);
      if (nextEnd == committedEnd) {
        return candidate;
      }
      committedEnd = nextEnd;
    }
    throw new IllegalStateException("Initial COMMIT length did not stabilize");
  }

  private static UnverifiedHeaderSlot placeholder(int index, RecordRef commitRef) {
    return new UnverifiedHeaderSlot(
        index,
        0,
        commitRef.recordId().bytes(),
        commitRef.offset(),
        commitRef.storedLength(),
        new byte[VaultFormat.HMAC_SHA256_BYTES]);
  }

  private static void writeFully(FileChannel channel, ByteBuffer source, long offset)
      throws IOException {
    long position = offset;
    while (source.hasRemaining()) {
      int written = channel.write(source, position);
      if (written <= 0) {
        throw new IOException("Unable to complete vault creation write");
      }
      position += written;
    }
  }

  private static void closeQuietly(FileChannel channel) {
    if (channel != null) {
      try {
        channel.close();
      } catch (IOException ignored) {
        // Cleanup remains best-effort and path-free.
      }
    }
  }
}
