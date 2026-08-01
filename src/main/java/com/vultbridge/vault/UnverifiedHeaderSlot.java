package com.vultbridge.vault;

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents structurally valid but unauthenticated public fields from one fixed-header slot.
 *
 * <p>The name is intentional: no commit identifier, offset, length, or generation may be trusted
 * until Step 9 verifies the slot tag with the unlocked header MAC key. Arrays are defensively
 * copied.
 */
public final class UnverifiedHeaderSlot {
  private final int slotIndex;
  private final long generation;
  private final byte[] commitRecordId;
  private final long commitOffset;
  private final long commitStoredLength;
  private final byte[] tag;

  /** Creates a structurally validated unauthenticated slot value. */
  public UnverifiedHeaderSlot(
      int slotIndex,
      long generation,
      byte[] commitRecordId,
      long commitOffset,
      long commitStoredLength,
      byte[] tag) {
    if (slotIndex != 0 && slotIndex != 1) {
      throw new IllegalArgumentException("Slot index must be zero or one");
    }
    this.slotIndex = slotIndex;
    this.generation = generation;
    this.commitRecordId =
        copyExact(commitRecordId, VaultFormat.RECORD_ID_BYTES, "commit record ID");
    this.commitOffset = commitOffset;
    this.commitStoredLength = commitStoredLength;
    this.tag = copyExact(tag, VaultFormat.HMAC_SHA256_BYTES, "slot tag");
  }

  /** Returns the physical and authenticated slot index. */
  public int slotIndex() {
    return slotIndex;
  }

  /** Returns the raw unsigned-64 generation bits; trust them only after authentication. */
  public long generation() {
    return generation;
  }

  /** Returns a copy of the unauthenticated commit record identifier. */
  public byte[] commitRecordId() {
    return Arrays.copyOf(commitRecordId, commitRecordId.length);
  }

  /** Returns the raw unsigned-64 commit offset bits; trust them only after authentication. */
  public long commitOffset() {
    return commitOffset;
  }

  /** Returns the raw unsigned-64 stored-length bits; trust them only after authentication. */
  public long commitStoredLength() {
    return commitStoredLength;
  }

  /** Returns a copy of the slot's expected HMAC-SHA-256 tag. */
  public byte[] tag() {
    return Arrays.copyOf(tag, tag.length);
  }

  private static byte[] copyExact(byte[] value, int expectedLength, String field) {
    Objects.requireNonNull(value, field);
    if (value.length != expectedLength) {
      throw new IllegalArgumentException(field + " has an invalid length");
    }
    return Arrays.copyOf(value, value.length);
  }
}
