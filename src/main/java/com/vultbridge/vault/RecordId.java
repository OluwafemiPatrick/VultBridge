package com.vultbridge.vault;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Represents one immutable 128-bit v1 record identifier.
 *
 * <p>Identifiers are public framing values rather than secrets, but byte arrays are defensively
 * copied so a caller cannot change key derivation, references, or session collision tracking after
 * validation.
 */
public final class RecordId {
  private final byte[] value;

  /** Copies an exact 16-byte identifier. */
  public RecordId(byte[] value) {
    Objects.requireNonNull(value, "value");
    if (value.length != VaultFormat.RECORD_ID_BYTES) {
      throw new IllegalArgumentException("Record ID must be exactly 16 bytes");
    }
    this.value = Arrays.copyOf(value, value.length);
  }

  /** Returns a caller-owned copy of the identifier bytes. */
  public byte[] bytes() {
    return Arrays.copyOf(value, value.length);
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof RecordId recordId && Arrays.equals(value, recordId.value);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(value);
  }

  @Override
  public String toString() {
    return HexFormat.of().formatHex(value);
  }
}
