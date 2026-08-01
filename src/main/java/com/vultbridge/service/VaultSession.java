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
  private final VaultSidecarLock sidecarLock;
  private final VaultKeySet keys;
  private final RecordIdGenerator recordIds;
  private final AuthenticatedHeaderSlot activeSlot;
  private VaultManifest manifest;
  private boolean closed;

  VaultSession(
      FileChannel channel,
      VaultSidecarLock sidecarLock,
      VaultKeySet keys,
      VaultManifest manifest,
      AuthenticatedHeaderSlot activeSlot) {
    this.channel = Objects.requireNonNull(channel, "channel");
    this.sidecarLock = Objects.requireNonNull(sidecarLock, "sidecarLock");
    this.keys = Objects.requireNonNull(keys, "keys");
    this.manifest = Objects.requireNonNull(manifest, "manifest");
    this.activeSlot = Objects.requireNonNull(activeSlot, "activeSlot");
    recordIds = new RecordIdGenerator();
  }

  /** Returns the authenticated metadata-only manifest while this session remains open. */
  public VaultManifest manifest() {
    ensureOpen();
    return manifest;
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
