package com.vultbridge.crypto;

import java.security.SecureRandom;
import java.util.Objects;

/** Production {@link RandomByteSource} backed by one application-owned {@link SecureRandom}. */
final class SecureRandomByteSource implements RandomByteSource {
  private final SecureRandom random;

  /** Creates a source using the platform's default securely seeded generator. */
  SecureRandomByteSource() {
    this(new SecureRandom());
  }

  SecureRandomByteSource(SecureRandom random) {
    this.random = Objects.requireNonNull(random, "random");
  }

  @Override
  public void nextBytes(byte[] destination) {
    random.nextBytes(Objects.requireNonNull(destination, "destination"));
  }
}
