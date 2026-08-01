package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.crypto.V1KeyHierarchy;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Verifies role-bound single-record and streaming FILE-chunk authenticated encryption. */
class RecordCryptoTest {
  @Test
  void manifestBodyRoundTripsOnlyUnderItsExactRoleAndId() throws VaultDataException {
    try (var fixture = fixture()) {
      RecordId id = new RecordId(new byte[16]);
      byte[] plaintext = ManifestCodec.encode(new VaultManifest(java.util.List.of()));
      byte[] encrypted =
          RecordCrypto.encryptSingleBody(fixture.keys(), id, RecordRole.MANIFEST, plaintext);
      try (var decrypted =
          RecordCrypto.decryptSingleBody(fixture.keys(), id, RecordRole.MANIFEST, encrypted)) {
        assertArrayEquals(plaintext, decrypted.copy());
      }
      assertThrows(
          VaultDataException.class,
          () -> RecordCrypto.decryptSingleBody(fixture.keys(), id, RecordRole.COMMIT, encrypted));
      assertThrows(
          VaultDataException.class,
          () ->
              RecordCrypto.decryptSingleBody(
                  fixture.keys(), id(1), RecordRole.MANIFEST, encrypted));
    }
  }

  @Test
  void everyTagByteMutationFailsWithoutPlaintext() {
    try (var fixture = fixture()) {
      RecordId id = id(2);
      byte[] encrypted =
          RecordCrypto.encryptSingleBody(
              fixture.keys(), id, RecordRole.COMMIT, new byte[] {1, 2, 3});
      for (int index = encrypted.length - VaultFormat.AEAD_TAG_BYTES;
          index < encrypted.length;
          index++) {
        byte[] changed = Arrays.copyOf(encrypted, encrypted.length);
        changed[index] ^= 1;
        assertThrows(
            VaultDataException.class,
            () -> RecordCrypto.decryptSingleBody(fixture.keys(), id, RecordRole.COMMIT, changed));
      }
    }
  }

  @Test
  void emptyFileChunkRoundTripsAndWrongIndexOrLengthFails() throws VaultDataException {
    try (var fixture = fixture()) {
      RecordId id = id(3);
      FileRecordLayout empty = FileRecordLayout.forLogicalSize(0);
      byte[] encrypted = RecordCrypto.encryptFileChunk(fixture.keys(), id, empty, 0, new byte[0]);
      try (var decrypted = RecordCrypto.decryptFileChunk(fixture.keys(), id, empty, 0, encrypted)) {
        assertArrayEquals(new byte[0], decrypted.copy());
      }
      assertThrows(
          IllegalArgumentException.class,
          () -> RecordCrypto.encryptFileChunk(fixture.keys(), id, empty, 0, new byte[1]));
      assertThrows(
          IllegalArgumentException.class,
          () -> RecordCrypto.encryptFileChunk(fixture.keys(), id, empty, 1, new byte[0]));
      assertThrows(
          VaultDataException.class,
          () ->
              RecordCrypto.decryptFileChunk(
                  fixture.keys(), id, empty, 0, Arrays.copyOf(encrypted, encrypted.length - 1)));
    }
  }

  @Test
  void fileChunkAuthenticationBindsItsIndexAndExactLength() {
    try (var fixture = fixture()) {
      RecordId id = id(4);
      FileRecordLayout layout =
          FileRecordLayout.forLogicalSize(VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES + 1L);
      byte[] finalChunk = {9};
      byte[] encrypted = RecordCrypto.encryptFileChunk(fixture.keys(), id, layout, 1, finalChunk);
      assertThrows(
          VaultDataException.class,
          () -> RecordCrypto.decryptFileChunk(fixture.keys(), id, layout, 0, encrypted));
    }
  }

  private static com.vultbridge.crypto.CreatedVaultKeySet fixture() {
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray())) {
      return V1KeyHierarchy.create(passphrase);
    }
  }

  private static RecordId id(int value) {
    byte[] bytes = new byte[16];
    bytes[15] = (byte) value;
    return new RecordId(bytes);
  }
}
