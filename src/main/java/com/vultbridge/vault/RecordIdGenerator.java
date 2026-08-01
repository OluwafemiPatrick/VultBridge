package com.vultbridge.vault;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Generates unique random record identifiers for one unlocked vault session.
 *
 * <p>The production constructor owns a securely seeded {@link SecureRandom}. A package-private
 * source seam supports deterministic collision tests. This class is not thread-safe and must be
 * confined to the serialized vault-operation worker that owns its session.
 */
public final class RecordIdGenerator {
  private static final int MAXIMUM_COLLISION_RETRIES = 128;
  private final ByteSource byteSource;
  private final Set<RecordId> generated = new HashSet<>();

  /** Creates a session generator backed by the platform secure-random provider. */
  public RecordIdGenerator() {
    SecureRandom secureRandom = new SecureRandom();
    byteSource = secureRandom::nextBytes;
  }

  RecordIdGenerator(ByteSource byteSource) {
    this.byteSource = Objects.requireNonNull(byteSource, "byteSource");
  }

  /** Returns a fresh session-unique identifier or fails if the source repeatedly collides. */
  public RecordId next() {
    for (int attempt = 0; attempt <= MAXIMUM_COLLISION_RETRIES; attempt++) {
      byte[] candidateBytes = new byte[VaultFormat.RECORD_ID_BYTES];
      byteSource.nextBytes(candidateBytes);
      var candidate = new RecordId(candidateBytes);
      if (generated.add(candidate)) {
        return candidate;
      }
    }
    throw new IllegalStateException("Unable to generate a unique record identifier");
  }

  /** Internal deterministic/failure seam; production callers cannot provide random bytes. */
  @FunctionalInterface
  interface ByteSource {
    /** Fills the complete caller-owned destination without retaining it. */
    void nextBytes(byte[] destination);
  }
}
