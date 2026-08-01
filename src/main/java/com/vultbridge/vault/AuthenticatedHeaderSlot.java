package com.vultbridge.vault;

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents header-slot fields whose HMAC has been verified with the unlocked vault's MAC key.
 *
 * <p>Authentication establishes the integrity of these public reference fields, but Phase 3 must
 * still validate the referenced COMMIT frame, bounds, role, ciphertext, and committed end before
 * using it. Arrays are defensively copied.
 */
public final class AuthenticatedHeaderSlot {
  private final int slotIndex;
  private final long generation;
  private final byte[] commitRecordId;
  private final long commitOffset;
  private final long commitStoredLength;

  AuthenticatedHeaderSlot(UnverifiedHeaderSlot verifiedSlot) {
    Objects.requireNonNull(verifiedSlot, "verifiedSlot");
    slotIndex = verifiedSlot.slotIndex();
    generation = verifiedSlot.generation();
    commitRecordId = verifiedSlot.commitRecordId();
    commitOffset = verifiedSlot.commitOffset();
    commitStoredLength = verifiedSlot.commitStoredLength();
  }

  /** Returns the authenticated physical slot index. */
  public int slotIndex() {
    return slotIndex;
  }

  /** Returns the authenticated generation as raw unsigned-64 bits. */
  public long generation() {
    return generation;
  }

  /** Returns a copy of the authenticated commit record identifier. */
  public byte[] commitRecordId() {
    return Arrays.copyOf(commitRecordId, commitRecordId.length);
  }

  /** Returns the authenticated commit offset as raw unsigned-64 bits. */
  public long commitOffset() {
    return commitOffset;
  }

  /** Returns the authenticated commit stored length as raw unsigned-64 bits. */
  public long commitStoredLength() {
    return commitStoredLength;
  }
}
