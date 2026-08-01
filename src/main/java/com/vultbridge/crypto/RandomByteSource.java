package com.vultbridge.crypto;

/**
 * Internal seam that supplies secure random bytes in production and deterministic bytes in tests.
 *
 * <p>The interface is package-private so callers outside the cryptographic engine cannot replace
 * production randomness. Tests in this package may inject deterministic or failing sources.
 */
@FunctionalInterface
interface RandomByteSource {
  /** Fills the complete caller-owned destination without retaining it. */
  void nextBytes(byte[] destination);
}
