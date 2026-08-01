package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Verifies canonical v1 encodings against literal byte strings independent of production helpers.
 */
class VaultEncodingTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final byte[] VAULT_ID = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
  private static final byte[] RECORD_ID = HEX.parseHex("101112131415161718191a1b1c1d1e1f");

  @Test
  void encodesUnsignedIntegersInBigEndianOrder() {
    assertArrayEquals(HEX.parseHex("00"), VaultEncoding.u8(0));
    assertArrayEquals(HEX.parseHex("ff"), VaultEncoding.u8(255));
    assertArrayEquals(HEX.parseHex("0000"), VaultEncoding.u16(0));
    assertArrayEquals(HEX.parseHex("ffff"), VaultEncoding.u16(65_535));
    assertArrayEquals(HEX.parseHex("00000000"), VaultEncoding.u32(0));
    assertArrayEquals(HEX.parseHex("ffffffff"), VaultEncoding.u32(0xffff_ffffL));
    assertArrayEquals(HEX.parseHex("ffffffffffffffff"), VaultEncoding.u64(-1L));
  }

  @Test
  void rejectsValuesOutsideCheckedUnsignedRanges() {
    assertThrows(IllegalArgumentException.class, () -> VaultEncoding.u8(-1));
    assertThrows(IllegalArgumentException.class, () -> VaultEncoding.u8(256));
    assertThrows(IllegalArgumentException.class, () -> VaultEncoding.u16(-1));
    assertThrows(IllegalArgumentException.class, () -> VaultEncoding.u16(65_536));
    assertThrows(IllegalArgumentException.class, () -> VaultEncoding.u32(-1));
    assertThrows(IllegalArgumentException.class, () -> VaultEncoding.u32(0x1_0000_0000L));
  }

  @Test
  void fixedPreludeMatchesTheV1Layout() {
    assertArrayEquals(
        HEX.parseHex("56554c5442524447000100010000006a"), VaultEncoding.fixedPrelude());
  }

  @Test
  void headerWrapAssociatedDataMatchesLiteralVector() {
    byte[] immutablePrefix =
        HEX.parseHex(
            "000102030405060708090a0b0c0d0e0f"
                + "0113"
                + "000100000000000300000001"
                + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b");

    assertArrayEquals(
        HEX.parseHex(
            "564c54422f76312f6865616465722d77726170"
                + "56554c5442524447000100010000006a"
                + HEX.formatHex(immutablePrefix)),
        VaultEncoding.headerWrapAssociatedData(immutablePrefix));
  }

  @Test
  void recordAssociatedDataMatchesLiteralVector() {
    assertArrayEquals(
        HEX.parseHex(
            "564c54422f76312f7265636f7264"
                + "0001"
                + "000102030405060708090a0b0c0d0e0f"
                + "101112131415161718191a1b1c1d1e1f"
                + "03"
                + "01020304"
                + "00400000"),
        VaultEncoding.recordAssociatedData(VAULT_ID, RECORD_ID, 3, 0x0102_0304L, 0x0040_0000L));
  }

  @Test
  void fileChunkNonceMatchesCanonicalU32LayoutAtEveryBoundary() {
    assertArrayEquals(HEX.parseHex("000000000000000000000000"), VaultEncoding.fileChunkNonce(0));
    assertArrayEquals(
        HEX.parseHex("000000000000000001020304"), VaultEncoding.fileChunkNonce(0x0102_0304L));
    assertArrayEquals(
        HEX.parseHex("0000000000000000ffffffff"), VaultEncoding.fileChunkNonce(0xffff_ffffL));
  }

  @Test
  void slotMacInputMatchesLiteralVector() {
    assertArrayEquals(
        HEX.parseHex(
            "564c54422f76312f6865616465722d736c6f74"
                + "000102030405060708090a0b0c0d0e0f"
                + "01"
                + "0102030405060708"
                + "101112131415161718191a1b1c1d1e1f"
                + "1112131415161718"
                + "2122232425262728"),
        VaultEncoding.slotMacInput(
            VAULT_ID,
            1,
            0x0102_0304_0506_0708L,
            RECORD_ID,
            0x1112_1314_1516_1718L,
            0x2122_2324_2526_2728L));
  }

  @Test
  void authenticatedEncodingsRejectInvalidLengthsRolesAndRanges() {
    assertThrows(
        IllegalArgumentException.class, () -> VaultEncoding.headerWrapAssociatedData(new byte[57]));
    assertThrows(
        IllegalArgumentException.class,
        () -> VaultEncoding.recordAssociatedData(new byte[15], RECORD_ID, 3, 0, 0));
    assertThrows(
        IllegalArgumentException.class,
        () -> VaultEncoding.recordAssociatedData(VAULT_ID, RECORD_ID, 4, 0, 0));
    assertThrows(
        IllegalArgumentException.class,
        () -> VaultEncoding.recordAssociatedData(VAULT_ID, RECORD_ID, 3, -1, 0));
    assertThrows(
        IllegalArgumentException.class,
        () -> VaultEncoding.slotMacInput(VAULT_ID, 2, 0, RECORD_ID, 0, 0));
    assertThrows(IllegalArgumentException.class, () -> VaultEncoding.fileChunkNonce(-1));
    assertThrows(
        IllegalArgumentException.class, () -> VaultEncoding.fileChunkNonce(0x1_0000_0000L));
  }
}
