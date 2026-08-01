package com.vultbridge.vault;

import java.util.Objects;

/**
 * Represents the public 24-byte framing header of one encrypted record.
 *
 * <p>The stored length is untrusted until compared with an authenticated {@link RecordRef}. It must
 * fit a non-negative Java {@code long}; no body allocation is implied by this value.
 */
public record RecordFrameHeader(RecordId recordId, long storedLength) {
  public RecordFrameHeader {
    Objects.requireNonNull(recordId, "recordId");
    if (storedLength < 0) {
      throw new IllegalArgumentException("Stored length must not be negative");
    }
  }
}
