package com.vultbridge.service;

import com.vultbridge.crypto.VaultKeySet;
import com.vultbridge.platform.VaultSidecarLock;
import com.vultbridge.vault.AuthenticatedHeaderSlot;
import com.vultbridge.vault.RecordIdGenerator;
import com.vultbridge.vault.VaultManifest;
import java.io.IOException;
import java.nio.channels.FileChannel;
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
  private final String vaultDisplayName;
  private final VaultSidecarLock sidecarLock;
  private final VaultKeySet keys;
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
      String vaultDisplayName) {
    this.channel = Objects.requireNonNull(channel, "channel");
    this.sidecarLock = Objects.requireNonNull(sidecarLock, "sidecarLock");
    this.keys = Objects.requireNonNull(keys, "keys");
    this.manifest = Objects.requireNonNull(manifest, "manifest");
    this.activeSlot = Objects.requireNonNull(activeSlot, "activeSlot");
    this.vaultDisplayName = Objects.requireNonNull(vaultDisplayName, "vaultDisplayName");
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
    keys.close();
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
