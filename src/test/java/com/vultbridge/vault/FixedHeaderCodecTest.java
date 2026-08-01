package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.crypto.Argon2idParameters;
import com.vultbridge.crypto.WrappedMasterKey;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** Verifies the exact fixed-header layout and strict structural parser behavior. */
class FixedHeaderCodecTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final String FIXED_HEADER_HEX =
      "56554c5442524447000100010000006a"
          + "000102030405060708090a0b0c0d0e0f"
          + "0113"
          + "000100000000000300000001"
          + "101112131415161718191a1b1c1d1e1f"
          + "202122232425262728292a2b"
          + "303132333435363738393a3b3c3d3e3f"
          + "404142434445464748494a4b4c4d4e4f"
          + "505152535455565758595a5b5c5d5e5f"
          + "0000000000000000"
          + "0000000000000001"
          + "606162636465666768696a6b6c6d6e6f"
          + "000000000000011a"
          + "0000000000000040"
          + "707172737475767778797a7b7c7d7e7f"
          + "808182838485868788898a8b8c8d8e8f"
          + "0100000000000000"
          + "ffffffffffffffff"
          + "909192939495969798999a9b9c9d9e9f"
          + "0000000000000200"
          + "0000000000000050"
          + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
          + "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

  @Test
  void encodingMatchesCompleteLiteralV1Header() {
    assertArrayEquals(HEX.parseHex(FIXED_HEADER_HEX), FixedHeaderCodec.encode(headerFixture()));
  }

  @Test
  void parsesAndReencodesEveryFieldExactly() throws HeaderParsingException {
    byte[] encoded = HEX.parseHex(FIXED_HEADER_HEX);
    UnverifiedFixedHeader parsed = FixedHeaderCodec.parse(encoded);

    assertArrayEquals(
        HEX.parseHex("000102030405060708090a0b0c0d0e0f"), parsed.wrappedMasterKey().vaultId());
    assertEquals(65_536, parsed.wrappedMasterKey().parameters().memoryKiB());
    assertEquals(0, parsed.slotA().slotIndex());
    assertEquals(1, parsed.slotA().generation());
    assertEquals(1, parsed.slotB().slotIndex());
    assertEquals(-1L, parsed.slotB().generation());
    assertEquals(0x200L, parsed.slotB().commitOffset());
    assertArrayEquals(encoded, FixedHeaderCodec.encode(parsed));
  }

  @Test
  void rejectsEveryMeaningfulTruncationAndTrailingData() {
    byte[] encoded = HEX.parseHex(FIXED_HEADER_HEX);
    int[] boundaries = {
      0, 7, 8, 10, 12, 15, 16, 31, 32, 33, 34, 38, 42, 46, 62, 74, 121, 122, 201, 202, 281
    };
    for (int boundary : boundaries) {
      byte[] truncated = Arrays.copyOf(encoded, boundary);
      assertThrows(HeaderParsingException.class, () -> FixedHeaderCodec.parse(truncated));
    }
    assertThrows(
        HeaderParsingException.class,
        () -> FixedHeaderCodec.parse(Arrays.copyOf(encoded, encoded.length + 1)));
  }

  @Test
  void rejectsWrongPreludeAlgorithmAndKdfBounds() {
    assertMutationRejected(0, 0x01);
    assertMutationRejected(9, 0x02);
    assertMutationRejected(11, 0x02);
    assertMutationRejected(15, 0x69);
    assertMutationRejected(32, 0x02);
    assertMutationRejected(33, 0x12);

    byte[] belowMemoryMinimum = HEX.parseHex(FIXED_HEADER_HEX);
    System.arraycopy(HEX.parseHex("00007fff"), 0, belowMemoryMinimum, 34, 4);
    assertThrows(HeaderParsingException.class, () -> FixedHeaderCodec.parse(belowMemoryMinimum));

    byte[] aboveIterationMaximum = HEX.parseHex(FIXED_HEADER_HEX);
    System.arraycopy(HEX.parseHex("0000000b"), 0, aboveIterationMaximum, 38, 4);
    assertThrows(HeaderParsingException.class, () -> FixedHeaderCodec.parse(aboveIterationMaximum));

    byte[] aboveParallelismMaximum = HEX.parseHex(FIXED_HEADER_HEX);
    System.arraycopy(HEX.parseHex("00000005"), 0, aboveParallelismMaximum, 42, 4);
    assertThrows(
        HeaderParsingException.class, () -> FixedHeaderCodec.parse(aboveParallelismMaximum));
  }

  @Test
  void rejectsNonzeroReservedBytesAndPhysicalSlotIndexMismatch() {
    assertMutationRejected(122, 0x01);
    assertMutationRejected(123, 0x01);
    assertMutationRejected(202, 0x00);
    assertMutationRejected(203, 0x01);
  }

  @Test
  void parsedModelsDoNotExposeMutableArrays() throws HeaderParsingException {
    UnverifiedFixedHeader parsed = FixedHeaderCodec.parse(HEX.parseHex(FIXED_HEADER_HEX));
    byte[] vaultId = parsed.wrappedMasterKey().vaultId();
    byte[] recordId = parsed.slotA().commitRecordId();
    byte[] tag = parsed.slotA().tag();
    vaultId[0] ^= 1;
    recordId[0] ^= 1;
    tag[0] ^= 1;

    assertEquals(0, parsed.wrappedMasterKey().vaultId()[0]);
    assertEquals(0x60, Byte.toUnsignedInt(parsed.slotA().commitRecordId()[0]));
    assertEquals(0x70, Byte.toUnsignedInt(parsed.slotA().tag()[0]));
  }

  private static UnverifiedFixedHeader headerFixture() {
    var envelope =
        new WrappedMasterKey(
            HEX.parseHex("000102030405060708090a0b0c0d0e0f"),
            Argon2idParameters.creationDefaults(),
            HEX.parseHex("101112131415161718191a1b1c1d1e1f"),
            HEX.parseHex("202122232425262728292a2b"),
            HEX.parseHex(
                "303132333435363738393a3b3c3d3e3f"
                    + "404142434445464748494a4b4c4d4e4f"
                    + "505152535455565758595a5b5c5d5e5f"));
    var slotA =
        new UnverifiedHeaderSlot(
            0,
            1,
            HEX.parseHex("606162636465666768696a6b6c6d6e6f"),
            0x11a,
            0x40,
            HEX.parseHex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"));
    var slotB =
        new UnverifiedHeaderSlot(
            1,
            -1L,
            HEX.parseHex("909192939495969798999a9b9c9d9e9f"),
            0x200,
            0x50,
            HEX.parseHex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"));
    return new UnverifiedFixedHeader(envelope, slotA, slotB);
  }

  private static void assertMutationRejected(int offset, int replacement) {
    byte[] changed = HEX.parseHex(FIXED_HEADER_HEX);
    changed[offset] = (byte) replacement;
    assertThrows(HeaderParsingException.class, () -> FixedHeaderCodec.parse(changed));
  }
}
