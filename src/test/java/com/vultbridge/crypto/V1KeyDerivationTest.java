package com.vultbridge.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.vault.VaultEncoding;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** Verifies HKDF domain separation and HMAC-SHA-256 against independently calculated vectors. */
class V1KeyDerivationTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final byte[] VAULT_ID = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
  private static final byte[] RECORD_ID = HEX.parseHex("101112131415161718191a1b1c1d1e1f");
  private static final byte[] MASTER_KEY =
      HEX.parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

  @Test
  void keyDerivationsMatchFixedIndependentVectors() {
    try (var masterKey = SensitiveBytes.copyOf(MASTER_KEY);
        var headerKey = V1KeyDerivation.deriveHeaderMacKey(masterKey, VAULT_ID);
        var recordKey = V1KeyDerivation.deriveRecordKey(masterKey, VAULT_ID, RECORD_ID)) {
      assertArrayEquals(
          HEX.parseHex("061f6472578b53f2b5e03409ac5c09bdebd1254f00b5609f1d3611fe5842cdf2"),
          headerKey.copy());
      assertArrayEquals(
          HEX.parseHex("d8dcb64e5953181caba209917e73de92149d79adc8f1d87531a7d8034eead928"),
          recordKey.copy());
      assertFalse(Arrays.equals(headerKey.copy(), recordKey.copy()));
    }
  }

  @Test
  void recordIdentifierChangesTheDerivedKey() {
    byte[] differentRecordId = Arrays.copyOf(RECORD_ID, RECORD_ID.length);
    differentRecordId[0] ^= 1;
    try (var masterKey = SensitiveBytes.copyOf(MASTER_KEY);
        var first = V1KeyDerivation.deriveRecordKey(masterKey, VAULT_ID, RECORD_ID);
        var second = V1KeyDerivation.deriveRecordKey(masterKey, VAULT_ID, differentRecordId)) {
      assertFalse(Arrays.equals(first.copy(), second.copy()));
    }
  }

  @Test
  void hmacMatchesFixedVectorAndDetectsMutations() {
    byte[] input =
        VaultEncoding.slotMacInput(
            VAULT_ID,
            1,
            0x0102_0304_0506_0708L,
            RECORD_ID,
            0x1112_1314_1516_1718L,
            0x2122_2324_2526_2728L);
    byte[] expected =
        HEX.parseHex("bc1e7e99ab1a350085797ba8166507f993673975ba1535e4f9eb8825c0aaea06");
    try (var masterKey = SensitiveBytes.copyOf(MASTER_KEY);
        var headerKey = V1KeyDerivation.deriveHeaderMacKey(masterKey, VAULT_ID)) {
      assertArrayEquals(expected, HmacSha256.authenticate(headerKey, input));
      assertTrue(HmacSha256.verify(headerKey, input, expected));

      byte[] changedInput = Arrays.copyOf(input, input.length);
      changedInput[changedInput.length - 1] ^= 1;
      assertFalse(HmacSha256.verify(headerKey, changedInput, expected));

      byte[] changedTag = Arrays.copyOf(expected, expected.length);
      changedTag[0] ^= 1;
      assertFalse(HmacSha256.verify(headerKey, input, changedTag));
      assertFalse(HmacSha256.verify(headerKey, input, new byte[31]));
    }
  }

  @Test
  void rejectsInvalidKeyAndIdentifierLengths() {
    try (var shortMasterKey = SensitiveBytes.copyOf(new byte[31]);
        var masterKey = SensitiveBytes.copyOf(MASTER_KEY);
        var shortHmacKey = SensitiveBytes.copyOf(new byte[31])) {
      assertThrows(
          IllegalArgumentException.class,
          () -> V1KeyDerivation.deriveHeaderMacKey(shortMasterKey, VAULT_ID));
      assertThrows(
          IllegalArgumentException.class,
          () -> V1KeyDerivation.deriveHeaderMacKey(masterKey, new byte[15]));
      assertThrows(
          IllegalArgumentException.class,
          () -> V1KeyDerivation.deriveRecordKey(masterKey, VAULT_ID, new byte[15]));
      assertThrows(
          IllegalArgumentException.class, () -> HmacSha256.authenticate(shortHmacKey, new byte[0]));
    }
  }
}
