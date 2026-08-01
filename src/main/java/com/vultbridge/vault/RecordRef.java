package com.vultbridge.vault;

import java.util.Objects;

/**
 * Represents an authenticated reference to one framed encrypted record.
 *
 * <p>Offsets and lengths must fit Java's non-negative signed {@code long} file APIs. Construction
 * rejects references inside the fixed header and checked-addition overflow. Before any seek, read,
 * allocation, or decryption, callers must invoke {@link #requireWithin(long)} using the
 * authenticated commit end.
 */
public record RecordRef(
    RecordId recordId, long offset, long storedLength, RecordRole expectedRole) {
  public RecordRef {
    Objects.requireNonNull(recordId, "recordId");
    Objects.requireNonNull(expectedRole, "expectedRole");
    if (offset < VaultFormat.FIXED_HEADER_BYTES || storedLength < 0) {
      throw new IllegalArgumentException("Record reference has an invalid range");
    }
    try {
      Math.addExact(Math.addExact(offset, VaultFormat.RECORD_FRAME_HEADER_BYTES), storedLength);
    } catch (ArithmeticException exception) {
      throw new IllegalArgumentException("Record reference range overflows", exception);
    }
  }

  /** Returns the checked exclusive end of the frame and encrypted body. */
  public long endOffset() {
    return Math.addExact(
        Math.addExact(offset, VaultFormat.RECORD_FRAME_HEADER_BYTES), storedLength);
  }

  /**
   * Rejects this reference unless its complete frame ends at or before an authenticated commit end.
   */
  public void requireWithin(long authenticatedCommitEnd) throws VaultDataException {
    if (authenticatedCommitEnd < VaultFormat.FIXED_HEADER_BYTES
        || endOffset() > authenticatedCommitEnd) {
      throw new VaultDataException();
    }
  }
}
