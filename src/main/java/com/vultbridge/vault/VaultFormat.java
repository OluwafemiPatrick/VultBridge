package com.vultbridge.vault;

/**
 * Defines the authoritative constants for the VultBridge v1 binary format and cryptographic suite.
 *
 * <p>Encoders, parsers, and cryptographic components must reference these values instead of
 * duplicating format numbers or lengths. This class contains public format information only and
 * never handles secret material.
 */
public final class VaultFormat {
  public static final String MAGIC = "VULTBRDG";
  public static final int FORMAT_MAJOR = 1;
  public static final int HEADER_VERSION = 1;
  public static final int KDF_ID_ARGON2ID = 1;
  public static final int ARGON2_VERSION_13 = 0x13;

  public static final int VAULT_ID_BYTES = 16;
  public static final int RECORD_ID_BYTES = 16;
  public static final int KDF_SALT_BYTES = 16;
  public static final int AEAD_KEY_BYTES = 32;
  public static final int AEAD_NONCE_BYTES = 12;
  public static final int AEAD_TAG_BYTES = 16;
  public static final int MASTER_VAULT_KEY_BYTES = 32;
  public static final int WRAPPED_MASTER_VAULT_KEY_BYTES = MASTER_VAULT_KEY_BYTES + AEAD_TAG_BYTES;
  public static final int HMAC_SHA256_BYTES = 32;

  public static final int MAXIMUM_FILE_COUNT = 10_000;
  public static final long MAXIMUM_LIVE_FILE_BYTES = 100L * 1024 * 1024 * 1024;
  public static final int FILE_CHUNK_PLAINTEXT_BYTES = 4 * 1024 * 1024;
  public static final int MAXIMUM_MANIFEST_PLAINTEXT_BYTES = 16 * 1024 * 1024;
  public static final int MAXIMUM_COMMIT_PLAINTEXT_BYTES = 64 * 1024;

  public static final int ARGON2_CREATE_MEMORY_KIB = 65_536;
  public static final int ARGON2_CREATE_ITERATIONS = 3;
  public static final int ARGON2_CREATE_PARALLELISM = 1;
  public static final int ARGON2_MIN_MEMORY_KIB = 32_768;
  public static final int ARGON2_MAX_MEMORY_KIB = 262_144;
  public static final int ARGON2_MIN_ITERATIONS = 1;
  public static final int ARGON2_MAX_ITERATIONS = 10;
  public static final int ARGON2_MIN_PARALLELISM = 1;
  public static final int ARGON2_MAX_PARALLELISM = 4;

  public static final int PRELUDE_BYTES = 16;
  public static final int IMMUTABLE_HEADER_PREFIX_BYTES = 58;
  public static final int IMMUTABLE_HEADER_BYTES = 106;
  public static final int HEADER_SLOT_BYTES = 80;
  public static final int FIXED_HEADER_BYTES =
      PRELUDE_BYTES + IMMUTABLE_HEADER_BYTES + (2 * HEADER_SLOT_BYTES);
  public static final int RECORD_FRAME_HEADER_BYTES = 24;

  public static final int ROLE_COMMIT = 1;
  public static final int ROLE_MANIFEST = 2;
  public static final int ROLE_FILE = 3;

  public static final String HEADER_WRAP_DOMAIN = "VLTB/v1/header-wrap";
  public static final String RECORD_DOMAIN = "VLTB/v1/record";
  public static final String HEADER_SLOT_MAC_DOMAIN = "VLTB/v1/header-slot";
  public static final String HEADER_SLOT_KEY_INFO = "VLTB/v1/header-slot-mac";
  public static final String RECORD_KEY_INFO = "VLTB/v1/record-key";

  private VaultFormat() {}
}
