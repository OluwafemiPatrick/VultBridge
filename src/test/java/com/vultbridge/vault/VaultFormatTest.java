package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Verifies that the authoritative v1 constants preserve the blueprint's exact binary layout. */
class VaultFormatTest {
  @Test
  void fixedHeaderSizesMatchTheirFieldLayout() {
    int expectedPreludeBytes = 8 + 2 + 2 + 4;
    int expectedImmutablePrefixBytes = 16 + 1 + 1 + 4 + 4 + 4 + 16 + 12;
    int expectedImmutableBytes = 16 + 1 + 1 + 4 + 4 + 4 + 16 + 12 + 48;
    int expectedSlotBytes = 1 + 7 + 8 + 16 + 8 + 8 + 32;

    assertEquals(expectedPreludeBytes, VaultFormat.PRELUDE_BYTES);
    assertEquals(expectedImmutablePrefixBytes, VaultFormat.IMMUTABLE_HEADER_PREFIX_BYTES);
    assertEquals(expectedImmutableBytes, VaultFormat.IMMUTABLE_HEADER_BYTES);
    assertEquals(expectedSlotBytes, VaultFormat.HEADER_SLOT_BYTES);
    assertEquals(282, VaultFormat.FIXED_HEADER_BYTES);
    assertEquals(24, VaultFormat.RECORD_FRAME_HEADER_BYTES);
  }

  @Test
  void fixedIdentifiersAndDomainsAreAsciiWithExpectedLengths() {
    assertEquals(8, VaultFormat.MAGIC.getBytes(StandardCharsets.US_ASCII).length);
    assertTrue(VaultFormat.HEADER_WRAP_DOMAIN.chars().allMatch(character -> character <= 0x7f));
    assertTrue(VaultFormat.RECORD_DOMAIN.chars().allMatch(character -> character <= 0x7f));
    assertTrue(VaultFormat.HEADER_SLOT_MAC_DOMAIN.chars().allMatch(character -> character <= 0x7f));
    assertTrue(VaultFormat.HEADER_SLOT_KEY_INFO.chars().allMatch(character -> character <= 0x7f));
    assertTrue(VaultFormat.RECORD_KEY_INFO.chars().allMatch(character -> character <= 0x7f));
  }

  @Test
  void creationKdfParametersAreWithinReaderBounds() {
    assertTrue(
        VaultFormat.ARGON2_CREATE_MEMORY_KIB >= VaultFormat.ARGON2_MIN_MEMORY_KIB
            && VaultFormat.ARGON2_CREATE_MEMORY_KIB <= VaultFormat.ARGON2_MAX_MEMORY_KIB);
    assertTrue(
        VaultFormat.ARGON2_CREATE_ITERATIONS >= VaultFormat.ARGON2_MIN_ITERATIONS
            && VaultFormat.ARGON2_CREATE_ITERATIONS <= VaultFormat.ARGON2_MAX_ITERATIONS);
    assertTrue(
        VaultFormat.ARGON2_CREATE_PARALLELISM >= VaultFormat.ARGON2_MIN_PARALLELISM
            && VaultFormat.ARGON2_CREATE_PARALLELISM <= VaultFormat.ARGON2_MAX_PARALLELISM);
  }

  @Test
  void parserAndVaultPolicyLimitsMatchTheV1Blueprint() {
    assertEquals(10_000, VaultFormat.MAXIMUM_FILE_COUNT);
    assertEquals(100L * 1024 * 1024 * 1024, VaultFormat.MAXIMUM_LIVE_FILE_BYTES);
    assertEquals(4 * 1024 * 1024, VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES);
    assertEquals(16 * 1024 * 1024, VaultFormat.MAXIMUM_MANIFEST_PLAINTEXT_BYTES);
    assertEquals(64 * 1024, VaultFormat.MAXIMUM_COMMIT_PLAINTEXT_BYTES);
    assertEquals(1024, VaultFormat.MAXIMUM_DISPLAY_NAME_UTF8_BYTES);
    assertEquals(1, VaultFormat.RECORD_SCHEMA_VERSION);
  }
}
