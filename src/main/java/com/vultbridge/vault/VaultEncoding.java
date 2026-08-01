package com.vultbridge.vault;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Produces every canonical fixed-width integer and authenticated byte sequence for vault format v1.
 *
 * <p>All integers are unsigned big-endian values. A Java {@code long} passed to the u64 encoder is
 * interpreted as its full unsigned 64-bit representation. Input arrays are validated, copied into
 * newly allocated output, and never retained.
 */
public final class VaultEncoding {
  private VaultEncoding() {}

  /** Encodes an unsigned 8-bit integer after checking its representable range. */
  public static byte[] u8(int value) {
    requireRange(value, 0xffL, "u8");
    return new byte[] {(byte) value};
  }

  /** Encodes an unsigned 16-bit integer after checking its representable range. */
  public static byte[] u16(int value) {
    requireRange(value, 0xffffL, "u16");
    return writtenBytes(allocate(Short.BYTES).putShort((short) value));
  }

  /** Encodes an unsigned 32-bit integer after checking its representable range. */
  public static byte[] u32(long value) {
    requireRange(value, 0xffff_ffffL, "u32");
    return writtenBytes(allocate(Integer.BYTES).putInt((int) value));
  }

  /** Encodes all 64 bits of a Java long as an unsigned big-endian integer. */
  public static byte[] u64(long value) {
    return writtenBytes(allocate(Long.BYTES).putLong(value));
  }

  /** Produces the exact fixed v1 prelude used in the header and header-wrap associated data. */
  public static byte[] fixedPrelude() {
    ByteBuffer output = allocate(VaultFormat.PRELUDE_BYTES);
    output.put(ascii(VaultFormat.MAGIC));
    putU16(output, VaultFormat.FORMAT_MAJOR);
    putU16(output, VaultFormat.HEADER_VERSION);
    putU32(output, VaultFormat.IMMUTABLE_HEADER_BYTES);
    return writtenBytes(output);
  }

  /** Produces the fixed HKDF info value used to derive the header-slot MAC key. */
  public static byte[] headerSlotKeyInfo() {
    return ascii(VaultFormat.HEADER_SLOT_KEY_INFO);
  }

  /** Produces the record-key HKDF info value bound to one exact record identifier. */
  public static byte[] recordKeyInfo(byte[] recordId) {
    requireLength(recordId, VaultFormat.RECORD_ID_BYTES, "record ID");
    byte[] domain = ascii(VaultFormat.RECORD_KEY_INFO);
    ByteBuffer output = allocate(domain.length + recordId.length);
    output.put(domain);
    output.put(recordId);
    return writtenBytes(output);
  }

  /**
   * Produces immutable-header fields from the vault ID through the wrap nonce, excluding
   * ciphertext.
   */
  public static byte[] immutableHeaderPrefix(
      byte[] vaultId,
      int kdfId,
      int argonVersion,
      long argonMemoryKiB,
      long argonIterations,
      long argonParallelism,
      byte[] kdfSalt,
      byte[] wrapNonce) {
    requireLength(vaultId, VaultFormat.VAULT_ID_BYTES, "vault ID");
    requireLength(kdfSalt, VaultFormat.KDF_SALT_BYTES, "KDF salt");
    requireLength(wrapNonce, VaultFormat.AEAD_NONCE_BYTES, "wrap nonce");
    if (kdfId != VaultFormat.KDF_ID_ARGON2ID) {
      throw new IllegalArgumentException("Unknown KDF identifier");
    }
    if (argonVersion != VaultFormat.ARGON2_VERSION_13) {
      throw new IllegalArgumentException("Unknown Argon2 version");
    }

    ByteBuffer output = allocate(VaultFormat.IMMUTABLE_HEADER_PREFIX_BYTES);
    output.put(vaultId);
    putU8(output, kdfId);
    putU8(output, argonVersion);
    putU32(output, argonMemoryKiB);
    putU32(output, argonIterations);
    putU32(output, argonParallelism);
    output.put(kdfSalt);
    output.put(wrapNonce);
    return writtenBytes(output);
  }

  /**
   * Produces header-wrap associated data from the fixed prelude and immutable fields through the
   * wrap nonce. The wrapped MVK is deliberately excluded to avoid circular authentication.
   */
  public static byte[] headerWrapAssociatedData(byte[] immutableHeaderThroughWrapNonce) {
    requireLength(
        immutableHeaderThroughWrapNonce,
        VaultFormat.IMMUTABLE_HEADER_PREFIX_BYTES,
        "immutable header prefix");
    byte[] domain = ascii(VaultFormat.HEADER_WRAP_DOMAIN);
    ByteBuffer output =
        allocate(
            domain.length + VaultFormat.PRELUDE_BYTES + immutableHeaderThroughWrapNonce.length);
    output.put(domain);
    output.put(fixedPrelude());
    output.put(immutableHeaderThroughWrapNonce);
    return writtenBytes(output);
  }

  /** Produces canonical record associated data for one role and chunk. */
  public static byte[] recordAssociatedData(
      byte[] vaultId, byte[] recordId, int role, long chunkIndex, long plaintextLength) {
    requireLength(vaultId, VaultFormat.VAULT_ID_BYTES, "vault ID");
    requireLength(recordId, VaultFormat.RECORD_ID_BYTES, "record ID");
    requireRole(role);
    requireRange(chunkIndex, 0xffff_ffffL, "chunk index");
    requireRange(plaintextLength, 0xffff_ffffL, "plaintext length");

    byte[] domain = ascii(VaultFormat.RECORD_DOMAIN);
    ByteBuffer output = allocate(domain.length + 2 + vaultId.length + recordId.length + 1 + 4 + 4);
    output.put(domain);
    putU16(output, VaultFormat.FORMAT_MAJOR);
    output.put(vaultId);
    output.put(recordId);
    putU8(output, role);
    putU32(output, chunkIndex);
    putU32(output, plaintextLength);
    return writtenBytes(output);
  }

  /**
   * Produces the canonical nonce for one FILE chunk.
   *
   * <p>The first eight bytes are zero and the final four bytes contain the chunk index as an
   * unsigned big-endian u32. Values outside the format's u32 range are rejected before encoding.
   */
  public static byte[] fileChunkNonce(long chunkIndex) {
    requireRange(chunkIndex, 0xffff_ffffL, "chunk index");
    ByteBuffer output = allocate(VaultFormat.AEAD_NONCE_BYTES);
    // Newly allocated ByteBuffers are zero-filled. Advancing by eight bytes preserves the required
    // zero prefix while the shared u32 writer supplies the canonical big-endian suffix.
    output.position(VaultFormat.AEAD_NONCE_BYTES - Integer.BYTES);
    putU32(output, chunkIndex);
    return writtenBytes(output);
  }

  /** Produces the all-zero nonce required by single-body MANIFEST and COMMIT records. */
  public static byte[] singleRecordNonce() {
    return new byte[VaultFormat.AEAD_NONCE_BYTES];
  }

  /** Produces the canonical HMAC input for one mutable header slot. */
  public static byte[] slotMacInput(
      byte[] vaultId,
      int slotIndex,
      long generation,
      byte[] commitRecordId,
      long commitOffset,
      long commitStoredLength) {
    requireLength(vaultId, VaultFormat.VAULT_ID_BYTES, "vault ID");
    requireLength(commitRecordId, VaultFormat.RECORD_ID_BYTES, "commit record ID");
    if (slotIndex != 0 && slotIndex != 1) {
      throw new IllegalArgumentException("Slot index must be zero or one");
    }

    byte[] domain = ascii(VaultFormat.HEADER_SLOT_MAC_DOMAIN);
    ByteBuffer output =
        allocate(domain.length + vaultId.length + 1 + 8 + commitRecordId.length + 8 + 8);
    output.put(domain);
    output.put(vaultId);
    putU8(output, slotIndex);
    putU64(output, generation);
    output.put(commitRecordId);
    putU64(output, commitOffset);
    putU64(output, commitStoredLength);
    return writtenBytes(output);
  }

  static void putU8(ByteBuffer output, int value) {
    output.put(u8(value));
  }

  static void putU16(ByteBuffer output, int value) {
    output.put(u16(value));
  }

  static void putU32(ByteBuffer output, long value) {
    output.put(u32(value));
  }

  static void putU64(ByteBuffer output, long value) {
    output.putLong(value);
  }

  private static ByteBuffer allocate(int size) {
    return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
  }

  private static byte[] writtenBytes(ByteBuffer output) {
    byte[] encoded = new byte[output.position()];
    output.flip();
    output.get(encoded);
    return encoded;
  }

  private static byte[] ascii(String value) {
    byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
    if (encoded.length != value.length()) {
      throw new IllegalStateException("Vault format domain is not ASCII");
    }
    return encoded;
  }

  private static void requireLength(byte[] value, int expected, String field) {
    Objects.requireNonNull(value, field);
    if (value.length != expected) {
      throw new IllegalArgumentException(field + " must be exactly " + expected + " bytes");
    }
  }

  private static void requireRange(long value, long maximum, String field) {
    if (value < 0 || value > maximum) {
      throw new IllegalArgumentException(field + " is outside its unsigned range");
    }
  }

  private static void requireRole(int role) {
    if (role != VaultFormat.ROLE_COMMIT
        && role != VaultFormat.ROLE_MANIFEST
        && role != VaultFormat.ROLE_FILE) {
      throw new IllegalArgumentException("Unknown record role");
    }
  }
}
