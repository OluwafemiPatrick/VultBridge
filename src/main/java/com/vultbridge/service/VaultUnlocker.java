package com.vultbridge.service;

import com.vultbridge.crypto.AuthenticationFailedException;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.crypto.V1KeyHierarchy;
import com.vultbridge.crypto.VaultKeySet;
import com.vultbridge.platform.VaultAccessException;
import com.vultbridge.platform.VaultAlreadyOpenException;
import com.vultbridge.platform.VaultSidecarLock;
import com.vultbridge.vault.AuthenticatedHeaderSlot;
import com.vultbridge.vault.CommitCodec;
import com.vultbridge.vault.FileRecordReader;
import com.vultbridge.vault.FixedHeaderCodec;
import com.vultbridge.vault.HeaderParsingException;
import com.vultbridge.vault.HeaderSlotAuthenticator;
import com.vultbridge.vault.ManifestCodec;
import com.vultbridge.vault.RecordCrypto;
import com.vultbridge.vault.RecordFrameCodec;
import com.vultbridge.vault.RecordId;
import com.vultbridge.vault.RecordRef;
import com.vultbridge.vault.RecordRole;
import com.vultbridge.vault.UnverifiedFixedHeader;
import com.vultbridge.vault.VaultCommit;
import com.vultbridge.vault.VaultDataException;
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
import java.util.Arrays;
import java.util.Objects;

/**
 * Performs the single complete trust-ordered vault unlock workflow.
 *
 * <p>It acquires the sidecar lock, structurally parses the fixed header, unwraps keys,
 * authenticates slots, tries COMMIT candidates by generation, authenticates and validates the
 * MANIFEST, compares totals, and only then constructs a metadata-bearing session. Authentication
 * and data failures collapse to {@link UnableToUnlockVaultException}; resources are released on
 * every failed path.
 */
public final class VaultUnlocker {
  private VaultUnlocker() {}

  /** Opens an existing regular non-symbolic vault and retains its sidecar lock in the session. */
  public static VaultSession open(Path vaultPath, SensitiveBytes passphrase)
      throws VaultAlreadyOpenException, VaultAccessException, UnableToUnlockVaultException {
    Objects.requireNonNull(vaultPath, "vaultPath");
    Objects.requireNonNull(passphrase, "passphrase");
    String vaultDisplayName = VaultPathPolicy.requireV1VaultFile(vaultPath);
    VaultSidecarLock sidecar = VaultSidecarLock.acquire(vaultPath);
    FileChannel channel = null;
    boolean transferred = false;
    try {
      BasicFileAttributes attributes =
          Files.readAttributes(vaultPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!attributes.isRegularFile()
          || Files.isSymbolicLink(vaultPath)
          || attributes.fileKey() == null) {
        throw new VaultAccessException();
      }
      channel =
          FileChannel.open(
              vaultPath,
              StandardOpenOption.READ,
              StandardOpenOption.WRITE,
              LinkOption.NOFOLLOW_LINKS);
      VaultSession session =
          openHeld(channel, sidecar, passphrase, vaultDisplayName, vaultPath, attributes.fileKey());
      transferred = true;
      return session;
    } catch (IOException | SecurityException exception) {
      throw new VaultAccessException();
    } finally {
      if (!transferred) {
        closeQuietly(channel);
        sidecar.close();
      }
    }
  }

  static VaultSession openHeld(
      FileChannel channel,
      VaultSidecarLock sidecar,
      SensitiveBytes passphrase,
      String vaultDisplayName,
      Path vaultPath,
      Object vaultFileKey)
      throws VaultAccessException, UnableToUnlockVaultException {
    VaultKeySet keys = null;
    boolean transferred = false;
    try {
      UnverifiedFixedHeader header = readHeader(channel);
      keys = V1KeyHierarchy.unwrapKeySet(passphrase, header.wrappedMasterKey());
      byte[] immutableHeader = immutableHeaderBytes(header);
      try {
        for (AuthenticatedHeaderSlot slot : HeaderSlotAuthenticator.verifyAndOrder(header, keys)) {
          try {
            VaultManifest manifest = readValidatedCandidate(channel, keys, slot);
            VaultSession session =
                new VaultSession(
                    channel,
                    sidecar,
                    keys,
                    manifest,
                    slot,
                    immutableHeader,
                    vaultDisplayName,
                    vaultPath,
                    vaultFileKey);
            transferred = true;
            return session;
          } catch (VaultDataException ignored) {
            // An invalid newer candidate does not suppress an older authenticated fallback slot.
          }
        }
      } finally {
        Arrays.fill(immutableHeader, (byte) 0);
      }
      throw new UnableToUnlockVaultException();
    } catch (HeaderParsingException
        | AuthenticationFailedException
        | VaultDataException exception) {
      throw new UnableToUnlockVaultException();
    } catch (IOException exception) {
      throw new VaultAccessException();
    } finally {
      if (!transferred && keys != null) {
        keys.close();
      }
    }
  }

  /**
   * Validates a published vault using an already-unlocked key set without taking ownership of it.
   *
   * <p>This is the compaction validation path. It acquires the published vault's sidecar lock,
   * executes the same header-slot/COMMIT/MANIFEST trust chain as normal unlock, returns metadata,
   * and closes only the temporary validation resources. The supplied key set remains owned by the
   * source session.
   */
  static VaultSnapshot validateWithKeys(
      Path vaultPath, VaultKeySet keys, byte[] expectedImmutableHeader)
      throws VaultAlreadyOpenException,
          VaultAccessException,
          UnableToUnlockVaultException,
          VaultOperationException {
    Objects.requireNonNull(vaultPath, "vaultPath");
    Objects.requireNonNull(keys, "keys");
    requireImmutableHeaderLength(expectedImmutableHeader);
    String vaultDisplayName = VaultPathPolicy.requireV1VaultFile(vaultPath);
    VaultSidecarLock sidecar = VaultSidecarLock.acquire(vaultPath);
    FileChannel channel = null;
    try {
      BasicFileAttributes attributes =
          Files.readAttributes(vaultPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!attributes.isRegularFile() || Files.isSymbolicLink(vaultPath)) {
        throw new VaultAccessException();
      }
      channel = FileChannel.open(vaultPath, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
      UnverifiedFixedHeader header = readHeader(channel);
      if (!immutableHeaderMatches(header, expectedImmutableHeader)) {
        throw new UnableToUnlockVaultException();
      }
      if (!Arrays.equals(header.wrappedMasterKey().vaultId(), keys.vaultId())) {
        throw new UnableToUnlockVaultException();
      }
      for (AuthenticatedHeaderSlot slot : HeaderSlotAuthenticator.verifyAndOrder(header, keys)) {
        try {
          VaultManifest manifest = readValidatedCandidate(channel, keys, slot);
          return new VaultSnapshot(vaultDisplayName, manifest, channel.size());
        } catch (VaultDataException ignored) {
          // Try the previous authenticated slot, matching the normal unlock fallback rule.
        }
      }
      throw new UnableToUnlockVaultException();
    } catch (HeaderParsingException | VaultDataException exception) {
      throw new UnableToUnlockVaultException();
    } catch (IOException exception) {
      throw new VaultAccessException();
    } finally {
      closeQuietly(channel);
      sidecar.close();
    }
  }

  /**
   * Opens a validated vault by transferring ownership of an already-unlocked key set.
   *
   * <p>The key set is closed on every failure and becomes owned by the returned session on success.
   * This is restricted to the serialized service worker and avoids passphrase re-entry when
   * compaction has already validated an output with the source MVK.
   */
  static VaultSession openWithKeys(
      Path vaultPath, VaultKeySet transferredKeys, byte[] expectedImmutableHeader)
      throws VaultAlreadyOpenException, VaultAccessException, UnableToUnlockVaultException {
    Objects.requireNonNull(vaultPath, "vaultPath");
    Objects.requireNonNull(transferredKeys, "transferredKeys");
    requireImmutableHeaderLength(expectedImmutableHeader);
    boolean transferred = false;
    VaultSidecarLock sidecar = null;
    FileChannel channel = null;
    try {
      String vaultDisplayName = VaultPathPolicy.requireV1VaultFile(vaultPath);
      sidecar = VaultSidecarLock.acquire(vaultPath);
      BasicFileAttributes attributes =
          Files.readAttributes(vaultPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (!attributes.isRegularFile()
          || Files.isSymbolicLink(vaultPath)
          || attributes.fileKey() == null) {
        throw new VaultAccessException();
      }
      channel =
          FileChannel.open(
              vaultPath,
              StandardOpenOption.READ,
              StandardOpenOption.WRITE,
              LinkOption.NOFOLLOW_LINKS);
      UnverifiedFixedHeader header = readHeader(channel);
      if (!immutableHeaderMatches(header, expectedImmutableHeader)) {
        throw new UnableToUnlockVaultException();
      }
      if (!Arrays.equals(header.wrappedMasterKey().vaultId(), transferredKeys.vaultId())) {
        throw new UnableToUnlockVaultException();
      }
      for (AuthenticatedHeaderSlot slot :
          HeaderSlotAuthenticator.verifyAndOrder(header, transferredKeys)) {
        try {
          VaultManifest manifest = readValidatedCandidate(channel, transferredKeys, slot);
          VaultSession session =
              new VaultSession(
                  channel,
                  sidecar,
                  transferredKeys,
                  manifest,
                  slot,
                  expectedImmutableHeader,
                  vaultDisplayName,
                  vaultPath,
                  attributes.fileKey());
          transferred = true;
          return session;
        } catch (VaultDataException ignored) {
          // An invalid newer slot does not suppress the older authenticated fallback slot.
        }
      }
      throw new UnableToUnlockVaultException();
    } catch (HeaderParsingException | VaultDataException exception) {
      throw new UnableToUnlockVaultException();
    } catch (IOException | SecurityException exception) {
      throw new VaultAccessException();
    } finally {
      if (!transferred) {
        closeQuietly(channel);
        if (sidecar != null) {
          sidecar.close();
        }
        transferredKeys.close();
      }
    }
  }

  /**
   * Reads and fully authenticates one committed candidate before returning any session metadata.
   *
   * <p>Manifest authentication alone is insufficient: the manifest contains references to FILE
   * records whose public framing and encrypted chunks must also be checked before a session can
   * expose its item list. Keeping this in the one candidate routine prevents normal unlock and
   * replacement validation from drifting into different trust decisions.
   */
  private static VaultManifest readValidatedCandidate(
      FileChannel channel, VaultKeySet keys, AuthenticatedHeaderSlot slot)
      throws IOException, VaultDataException {
    RecordRef commitRef;
    try {
      // Slot u64 fields are retained as raw long bits during structural parsing. Promote them into
      // Java's signed file-address range only after HMAC verification, mapping unsupported unsigned
      // values to the same safe candidate failure so an older authenticated slot can still open.
      commitRef =
          new RecordRef(
              new RecordId(slot.commitRecordId()),
              slot.commitOffset(),
              slot.commitStoredLength(),
              RecordRole.COMMIT);
    } catch (IllegalArgumentException exception) {
      throw new VaultDataException();
    }
    byte[] encryptedCommit =
        RecordFrameCodec.readBoundedBody(
            channel,
            commitRef,
            commitRef.endOffset(),
            VaultFormat.MAXIMUM_COMMIT_PLAINTEXT_BYTES + VaultFormat.AEAD_TAG_BYTES);
    VaultCommit commit;
    try (var plaintext =
        RecordCrypto.decryptSingleBody(
            keys, commitRef.recordId(), RecordRole.COMMIT, encryptedCommit)) {
      byte[] copy = plaintext.copy();
      try {
        commit = CommitCodec.decode(copy);
      } finally {
        java.util.Arrays.fill(copy, (byte) 0);
      }
    }
    if (commit.committedEnd() != commitRef.endOffset()) {
      throw new VaultDataException();
    }

    RecordRef manifestRef = commit.manifestRef();
    byte[] encryptedManifest =
        RecordFrameCodec.readBoundedBody(
            channel,
            manifestRef,
            commit.committedEnd(),
            VaultFormat.MAXIMUM_MANIFEST_PLAINTEXT_BYTES + VaultFormat.AEAD_TAG_BYTES);
    VaultManifest manifest;
    try (var plaintext =
        RecordCrypto.decryptSingleBody(
            keys, manifestRef.recordId(), RecordRole.MANIFEST, encryptedManifest)) {
      byte[] copy = plaintext.copy();
      try {
        manifest = ManifestCodec.decode(copy);
      } finally {
        java.util.Arrays.fill(copy, (byte) 0);
      }
    }
    commit.requireConsistentWith(commitRef, manifest);
    verifyFileRecords(channel, keys, manifest, slot);
    return manifest;
  }

  private static void verifyFileRecords(
      FileChannel channel, VaultKeySet keys, VaultManifest manifest, AuthenticatedHeaderSlot slot)
      throws IOException, VaultDataException {
    long committedEnd;
    try {
      committedEnd =
          Math.addExact(
              Math.addExact(slot.commitOffset(), VaultFormat.RECORD_FRAME_HEADER_BYTES),
              slot.commitStoredLength());
    } catch (ArithmeticException exception) {
      throw new VaultDataException();
    }
    for (var entry : manifest.entries()) {
      FileRecordReader.verify(channel, keys, entry, committedEnd, () -> false);
    }
  }

  private static UnverifiedFixedHeader readHeader(FileChannel channel)
      throws IOException, HeaderParsingException, VaultDataException {
    if (channel.size() < VaultFormat.FIXED_HEADER_BYTES) {
      throw new VaultDataException();
    }
    ByteBuffer input = ByteBuffer.allocate(VaultFormat.FIXED_HEADER_BYTES);
    long position = 0;
    while (input.hasRemaining()) {
      int read = channel.read(input, position);
      if (read <= 0) {
        throw new VaultDataException();
      }
      position += read;
    }
    return FixedHeaderCodec.parse(input.array());
  }

  private static byte[] immutableHeaderBytes(UnverifiedFixedHeader header) {
    byte[] encoded = FixedHeaderCodec.encode(header);
    try {
      return Arrays.copyOf(encoded, VaultFormat.PRELUDE_BYTES + VaultFormat.IMMUTABLE_HEADER_BYTES);
    } finally {
      Arrays.fill(encoded, (byte) 0);
    }
  }

  private static boolean immutableHeaderMatches(
      UnverifiedFixedHeader header, byte[] expectedImmutableHeader) {
    byte[] candidate = immutableHeaderBytes(header);
    try {
      return Arrays.equals(candidate, expectedImmutableHeader);
    } finally {
      Arrays.fill(candidate, (byte) 0);
    }
  }

  private static void requireImmutableHeaderLength(byte[] immutableHeader) {
    Objects.requireNonNull(immutableHeader, "expectedImmutableHeader");
    if (immutableHeader.length != VaultFormat.PRELUDE_BYTES + VaultFormat.IMMUTABLE_HEADER_BYTES) {
      throw new IllegalArgumentException("Immutable header has an invalid length");
    }
  }

  private static void closeQuietly(FileChannel channel) {
    if (channel != null) {
      try {
        channel.close();
      } catch (IOException ignored) {
        // The public failure remains sanitized.
      }
    }
  }
}
