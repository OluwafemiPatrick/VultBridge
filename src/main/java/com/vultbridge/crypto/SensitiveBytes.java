package com.vultbridge.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * Owns a mutable byte array containing short-lived sensitive material and wipes it when closed.
 *
 * <p>The {@code copyOf} factory copies caller-owned input, so closing this object never modifies
 * the caller's array. Crypto-package implementations may temporarily borrow the owned array but
 * must not retain, return, or resize it. This class is not thread-safe; ownership belongs to one
 * operation.
 */
public final class SensitiveBytes implements AutoCloseable {
  private byte[] value;

  private SensitiveBytes(byte[] ownedValue) {
    value = ownedValue;
  }

  /** Copies sensitive input into a new independently owned buffer. */
  public static SensitiveBytes copyOf(byte[] input) {
    Objects.requireNonNull(input, "input");
    return new SensitiveBytes(Arrays.copyOf(input, input.length));
  }

  /** Returns the number of bytes while the buffer remains open. */
  public int length() {
    ensureOpen();
    return value.length;
  }

  /** Returns a caller-owned copy whose contents the caller is responsible for wiping. */
  public byte[] copy() {
    ensureOpen();
    return Arrays.copyOf(value, value.length);
  }

  /** Returns whether this object has wiped and released its owned buffer. */
  public boolean isDestroyed() {
    return value == null;
  }

  @Override
  public void close() {
    if (value != null) {
      Arrays.fill(value, (byte) 0);
      value = null;
    }
  }

  // Package-private borrowing avoids extra secret copies inside crypto operations. The returned
  // array remains owned by this object and is valid only for the immediate synchronous call.
  byte[] borrow() {
    ensureOpen();
    return value;
  }

  private void ensureOpen() {
    if (value == null) {
      throw new IllegalStateException("Sensitive buffer has been destroyed");
    }
  }
}
