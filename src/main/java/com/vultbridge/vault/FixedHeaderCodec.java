package com.vultbridge.vault;

import com.vultbridge.crypto.Argon2idParameters;
import com.vultbridge.crypto.WrappedMasterKey;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Serializes and structurally parses the exact 282-byte VultBridge v1 fixed header.
 *
 * <p>Parsing validates every public constant, KDF bound, reserved byte, field width, physical slot
 * index, and total length before returning an explicitly unauthenticated model. This codec performs
 * no KDF, decryption, MAC verification, allocation based on header values, or filesystem I/O.
 */
public final class FixedHeaderCodec {
  private static final byte[] MAGIC = VaultFormat.MAGIC.getBytes(StandardCharsets.US_ASCII);

  private FixedHeaderCodec() {}

  /** Encodes one validated unverified header in the exact fixed v1 field order. */
  public static byte[] encode(UnverifiedFixedHeader header) {
    Objects.requireNonNull(header, "header");
    byte[] encoded = new byte[VaultFormat.FIXED_HEADER_BYTES];
    ByteBuffer output = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
    output.put(VaultEncoding.fixedPrelude());
    writeImmutable(output, header.wrappedMasterKey());
    writeSlot(output, header.slotA());
    writeSlot(output, header.slotB());
    if (output.hasRemaining()) {
      throw new IllegalStateException("Fixed header encoder did not fill its exact output");
    }
    return encoded;
  }

  /** Encodes one complete authenticated-slot representation for positional installation. */
  public static byte[] encodeSlot(UnverifiedHeaderSlot slot) {
    Objects.requireNonNull(slot, "slot");
    ByteBuffer output =
        ByteBuffer.allocate(VaultFormat.HEADER_SLOT_BYTES).order(ByteOrder.BIG_ENDIAN);
    writeSlot(output, slot);
    return output.array();
  }

  /** Parses exactly one fixed header without authenticating its wrapped key or slots. */
  public static UnverifiedFixedHeader parse(byte[] encoded) throws HeaderParsingException {
    Objects.requireNonNull(encoded, "encoded");
    if (encoded.length != VaultFormat.FIXED_HEADER_BYTES) {
      throw new HeaderParsingException();
    }

    ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
    byte[] magic = readBytes(input, MAGIC.length);
    if (!Arrays.equals(MAGIC, magic)
        || readU16(input) != VaultFormat.FORMAT_MAJOR
        || readU16(input) != VaultFormat.HEADER_VERSION
        || readU32(input) != VaultFormat.IMMUTABLE_HEADER_BYTES) {
      throw new HeaderParsingException();
    }

    byte[] vaultId = readBytes(input, VaultFormat.VAULT_ID_BYTES);
    int kdfId = readU8(input);
    int argonVersion = readU8(input);
    long memoryKiB = readU32(input);
    long iterations = readU32(input);
    long parallelism = readU32(input);
    if (kdfId != VaultFormat.KDF_ID_ARGON2ID
        || argonVersion != VaultFormat.ARGON2_VERSION_13
        || memoryKiB > Integer.MAX_VALUE
        || iterations > Integer.MAX_VALUE
        || parallelism > Integer.MAX_VALUE) {
      throw new HeaderParsingException();
    }

    Argon2idParameters parameters;
    try {
      parameters = new Argon2idParameters((int) memoryKiB, (int) iterations, (int) parallelism);
    } catch (IllegalArgumentException exception) {
      throw new HeaderParsingException();
    }

    byte[] salt = readBytes(input, VaultFormat.KDF_SALT_BYTES);
    byte[] nonce = readBytes(input, VaultFormat.AEAD_NONCE_BYTES);
    byte[] wrappedKey = readBytes(input, VaultFormat.WRAPPED_MASTER_VAULT_KEY_BYTES);
    var envelope = new WrappedMasterKey(vaultId, parameters, salt, nonce, wrappedKey);
    UnverifiedHeaderSlot slotA = readSlot(input, 0);
    UnverifiedHeaderSlot slotB = readSlot(input, 1);
    if (input.hasRemaining()) {
      throw new HeaderParsingException();
    }
    return new UnverifiedFixedHeader(envelope, slotA, slotB);
  }

  private static void writeImmutable(ByteBuffer output, WrappedMasterKey envelope) {
    Argon2idParameters parameters = envelope.parameters();
    output.put(envelope.vaultId());
    VaultEncoding.putU8(output, VaultFormat.KDF_ID_ARGON2ID);
    VaultEncoding.putU8(output, VaultFormat.ARGON2_VERSION_13);
    VaultEncoding.putU32(output, parameters.memoryKiB());
    VaultEncoding.putU32(output, parameters.iterations());
    VaultEncoding.putU32(output, parameters.parallelism());
    output.put(envelope.kdfSalt());
    output.put(envelope.wrapNonce());
    output.put(envelope.wrappedKey());
  }

  private static void writeSlot(ByteBuffer output, UnverifiedHeaderSlot slot) {
    VaultEncoding.putU8(output, slot.slotIndex());
    output.put(new byte[7]);
    VaultEncoding.putU64(output, slot.generation());
    output.put(slot.commitRecordId());
    VaultEncoding.putU64(output, slot.commitOffset());
    VaultEncoding.putU64(output, slot.commitStoredLength());
    output.put(slot.tag());
  }

  private static UnverifiedHeaderSlot readSlot(ByteBuffer input, int physicalIndex)
      throws HeaderParsingException {
    int slotIndex = readU8(input);
    byte[] reserved = readBytes(input, 7);
    if (slotIndex != physicalIndex || !allZero(reserved)) {
      throw new HeaderParsingException();
    }
    return new UnverifiedHeaderSlot(
        slotIndex,
        input.getLong(),
        readBytes(input, VaultFormat.RECORD_ID_BYTES),
        input.getLong(),
        input.getLong(),
        readBytes(input, VaultFormat.HMAC_SHA256_BYTES));
  }

  private static boolean allZero(byte[] values) {
    int combined = 0;
    for (byte value : values) {
      combined |= value;
    }
    return combined == 0;
  }

  private static int readU8(ByteBuffer input) {
    return Byte.toUnsignedInt(input.get());
  }

  private static int readU16(ByteBuffer input) {
    return Short.toUnsignedInt(input.getShort());
  }

  private static long readU32(ByteBuffer input) {
    return Integer.toUnsignedLong(input.getInt());
  }

  private static byte[] readBytes(ByteBuffer input, int length) {
    byte[] value = new byte[length];
    input.get(value);
    return value;
  }
}
