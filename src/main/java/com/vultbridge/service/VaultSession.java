package com.vultbridge.service;

import com.vultbridge.crypto.VaultKeySet;
import com.vultbridge.platform.VaultSidecarLock;
import com.vultbridge.vault.AuthenticatedHeaderSlot;
import com.vultbridge.vault.RecordIdGenerator;
import com.vultbridge.vault.VaultManifest;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Objects;

/**
 * Owns all resources and authenticated metadata for one unlocked vault session.
 *
 * <p>The session retains the vault channel, exclusive sidecar lock, sensitive key set,
 * authenticated metadata, and session-local record-ID guard. It is confined to the serialized vault
 * worker. Closing is idempotent, clears metadata, wipes keys, closes the channel, and releases the
 * lock.
 */
public final class VaultSession implements AutoCloseable {
  private final FileChannel channel;
  private final Path vaultPath;
  private final String vaultDisplayName;
  private final VaultSidecarLock sidecarLock;
  private final byte[] immutableHeader;
  private VaultKeySet keys;
  private final Object vaultFileKey;
  private final RecordIdGenerator recordIds;
  private AuthenticatedHeaderSlot activeSlot;
  private VaultManifest manifest;
  private boolean closed;

  VaultSession(
      FileChannel channel,
      VaultSidecarLock sidecarLock,
      VaultKeySet keys,
      VaultManifest manifest,
      AuthenticatedHeaderSlot activeSlot,
      byte[] immutableHeader,
      String vaultDisplayName,
      Path vaultPath,
      Object vaultFileKey) {
    this.channel = Objects.requireNonNull(channel, "channel");
    this.sidecarLock = Objects.requireNonNull(sidecarLock, "sidecarLock");
    this.keys = Objects.requireNonNull(keys, "keys");
    this.manifest = Objects.requireNonNull(manifest, "manifest");
    this.activeSlot = Objects.requireNonNull(activeSlot, "activeSlot");
    this.immutableHeader =
        Arrays.copyOf(
            Objects.requireNonNull(immutableHeader, "immutableHeader"), immutableHeader.length);
    this.vaultDisplayName = Objects.requireNonNull(vaultDisplayName, "vaultDisplayName");
    this.vaultPath = Objects.requireNonNull(vaultPath, "vaultPath").toAbsolutePath().normalize();
    this.vaultFileKey = Objects.requireNonNull(vaultFileKey, "vaultFileKey");
    if (vaultDisplayName.isBlank()) {
      throw new IllegalArgumentException("Vault display name must not be blank");
    }
    recordIds = new RecordIdGenerator();
  }

  /** Returns the authenticated metadata-only manifest while this session remains open. */
  public VaultManifest manifest() {
    ensureOpen();
    return manifest;
  }

  /** Returns only the final vault filename, never its complete host path. */
  public String vaultDisplayName() {
    ensureOpen();
    return vaultDisplayName;
  }

  /**
   * Returns the exact normalized absolute path retained for this session's vault file.
   *
   * <p>This path is available only inside the service boundary. It is never copied into {@link
   * VaultSnapshot} or application UI state, and it must be used directly for any future source
   * operation rather than rediscovering a file by name.
   */
  Path vaultPath() {
    ensureOpen();
    return vaultPath;
  }

  /** Returns whether the retained source path still identifies this session's opened inode. */
  boolean sourceIdentityMatches() {
    ensureOpen();
    try {
      BasicFileAttributes attributes =
          Files.readAttributes(vaultPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      return attributes.isRegularFile()
          && !attributes.isSymbolicLink()
          && vaultFileKey.equals(attributes.fileKey());
    } catch (IOException | SecurityException exception) {
      return false;
    }
  }

  /** Transfers key ownership to a replacement session after the source has been validated. */
  VaultKeySet detachKeysForReplacement() {
    ensureOpen();
    if (keys == null) {
      throw new IllegalStateException("Session keys have already been transferred");
    }
    VaultKeySet transferred = keys;
    keys = null;
    return transferred;
  }

  /** Returns a fresh authenticated metadata snapshot including the current physical file size. */
  public VaultSnapshot snapshot() throws VaultOperationException {
    ensureOpen();
    try {
      return new VaultSnapshot(vaultDisplayName, manifest, channel.size());
    } catch (IOException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    }
  }

  /** Returns whether all owned session resources have been released. */
  public boolean isClosed() {
    return closed;
  }

  FileChannel channel() {
    ensureOpen();
    return channel;
  }

  VaultKeySet keys() {
    ensureOpen();
    return keys;
  }

  /** Returns a defensive copy of the authenticated immutable fixed-header bytes. */
  byte[] immutableHeader() {
    ensureOpen();
    return Arrays.copyOf(immutableHeader, immutableHeader.length);
  }

  RecordIdGenerator recordIds() {
    ensureOpen();
    return recordIds;
  }

  AuthenticatedHeaderSlot activeSlot() {
    ensureOpen();
    return activeSlot;
  }

  long authenticatedCommitEnd() {
    ensureOpen();
    return Math.addExact(
        Math.addExact(
            activeSlot.commitOffset(), com.vultbridge.vault.VaultFormat.RECORD_FRAME_HEADER_BYTES),
        activeSlot.commitStoredLength());
  }

  /**
   * Advances authenticated session state after the matching inactive slot has been forced.
   *
   * <p>This package-private transition is confined to the serialized vault worker. Both values are
   * validated before either field changes, so rejected transitions retain the preceding in-memory
   * state exactly as the on-disk two-slot protocol retains the preceding committed state.
   */
  void installCommittedState(VaultManifest nextManifest, AuthenticatedHeaderSlot nextActiveSlot) {
    ensureOpen();
    Objects.requireNonNull(nextManifest, "nextManifest");
    Objects.requireNonNull(nextActiveSlot, "nextActiveSlot");
    if (activeSlot.generation() == -1L
        || nextActiveSlot.slotIndex() != 1 - activeSlot.slotIndex()
        || nextActiveSlot.generation() != activeSlot.generation() + 1) {
      throw new IllegalArgumentException("Session state must advance to the next inactive slot");
    }
    manifest = nextManifest;
    activeSlot = nextActiveSlot;
  }

  @Override
  public void close() {
    if (closed) {
      return;
    }
    closed = true;
    manifest = null;
    Arrays.fill(immutableHeader, (byte) 0);
    if (keys != null) {
      keys.close();
      keys = null;
    }
    try {
      channel.close();
    } catch (IOException ignored) {
      // Session shutdown cannot safely surface raw path-bearing filesystem details.
    } finally {
      sidecarLock.close();
    }
  }

  private void ensureOpen() {
    if (closed) {
      throw new IllegalStateException("Vault session is closed");
    }
  }
}
