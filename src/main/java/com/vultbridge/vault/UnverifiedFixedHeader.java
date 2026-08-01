package com.vultbridge.vault;

import com.vultbridge.crypto.WrappedMasterKey;
import java.util.Objects;

/**
 * Represents a structurally valid v1 fixed header whose wrapped key and slots are not
 * authenticated.
 *
 * <p>Parsing this value is never evidence that a passphrase, master key, or commit reference is
 * valid. Authentication is performed by the cryptographic key hierarchy and slot verifier.
 */
public record UnverifiedFixedHeader(
    WrappedMasterKey wrappedMasterKey, UnverifiedHeaderSlot slotA, UnverifiedHeaderSlot slotB) {
  public UnverifiedFixedHeader {
    Objects.requireNonNull(wrappedMasterKey, "wrappedMasterKey");
    Objects.requireNonNull(slotA, "slotA");
    Objects.requireNonNull(slotB, "slotB");
    if (slotA.slotIndex() != 0 || slotB.slotIndex() != 1) {
      throw new IllegalArgumentException("Header slots must match their physical positions");
    }
  }
}
