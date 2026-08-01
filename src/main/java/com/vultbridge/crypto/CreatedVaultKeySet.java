package com.vultbridge.crypto;

import java.util.Objects;

/**
 * Couples a new vault's public wrapped-key envelope with its live, sensitive session keys.
 *
 * <p>Closing this result delegates to the owned {@link VaultKeySet}. The immutable envelope remains
 * available because it contains only public header fields and authenticated ciphertext.
 */
public record CreatedVaultKeySet(WrappedMasterKey wrappedMasterKey, VaultKeySet keys)
    implements AutoCloseable {
  public CreatedVaultKeySet {
    Objects.requireNonNull(wrappedMasterKey, "wrappedMasterKey");
    Objects.requireNonNull(keys, "keys");
  }

  @Override
  public void close() {
    keys.close();
  }
}
