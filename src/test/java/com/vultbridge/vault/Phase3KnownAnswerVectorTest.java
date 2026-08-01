package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.AuthenticationFailedException;
import com.vultbridge.crypto.HmacSha256;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.crypto.V1KeyDerivation;
import com.vultbridge.crypto.V1KeyHierarchy;
import com.vultbridge.platform.VaultAccessException;
import com.vultbridge.platform.VaultAlreadyOpenException;
import com.vultbridge.service.UnableToUnlockVaultException;
import com.vultbridge.service.VaultUnlocker;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies the complete Phase 3 empty-vault artifact against immutable independent bytes.
 *
 * <p>The resource was produced with literal canonical CBOR and Node.js/OpenSSL primitives. These
 * tests reconstruct every record, frame, and header slot through the production implementation,
 * then prove that the standard unlock workflow accepts the independently composed vault.
 */
class Phase3KnownAnswerVectorTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final String RESOURCE = "/com/vultbridge/vectors/v1-phase3-empty.properties";

  @TempDir Path temporaryDirectory;

  @Test
  void everyEmptyVaultArtifactMatchesTheIndependentVector()
      throws IOException, HeaderParsingException, AuthenticationFailedException {
    Properties vector = loadVector();
    byte[] fixedHeader = bytes(vector, "fixedHeader");
    UnverifiedFixedHeader parsed = FixedHeaderCodec.parse(fixedHeader);

    try (var passphrase = SensitiveBytes.copyOf(bytes(vector, "passphraseHex"));
        var keys = V1KeyHierarchy.unwrapKeySet(passphrase, parsed.wrappedMasterKey())) {
      var manifestId = new RecordId(bytes(vector, "manifestRecordId"));
      var commitId = new RecordId(bytes(vector, "commitRecordId"));
      var emptyFileId = new RecordId(bytes(vector, "emptyFileRecordId"));

      assertRecordKey(vector, keys, manifestId, "manifestRecordKey");
      assertRecordKey(vector, keys, commitId, "commitRecordKey");
      assertRecordKey(vector, keys, emptyFileId, "emptyFileRecordKey");

      var emptyManifest = new VaultManifest(List.of());
      byte[] manifestPlaintext = ManifestCodec.encode(emptyManifest);
      assertArrayEquals(bytes(vector, "manifestPlaintext"), manifestPlaintext);
      assertArrayEquals(
          bytes(vector, "manifestAad"),
          VaultEncoding.recordAssociatedData(
              keys.vaultId(), manifestId.bytes(), RecordRole.MANIFEST.code(), 0, 4));
      byte[] manifestCiphertext =
          RecordCrypto.encryptSingleBody(keys, manifestId, RecordRole.MANIFEST, manifestPlaintext);
      assertArrayEquals(bytes(vector, "manifestCiphertext"), manifestCiphertext);
      assertArrayEquals(bytes(vector, "manifestFrame"), frame(manifestId, manifestCiphertext));

      var manifestRef = new RecordRef(manifestId, 282, 20, RecordRole.MANIFEST);
      var commit = new VaultCommit(manifestRef, 397, 0, 0);
      byte[] commitPlaintext = CommitCodec.encode(commit);
      assertArrayEquals(bytes(vector, "commitPlaintext"), commitPlaintext);
      assertArrayEquals(
          bytes(vector, "commitAad"),
          VaultEncoding.recordAssociatedData(
              keys.vaultId(), commitId.bytes(), RecordRole.COMMIT.code(), 0, 31));
      byte[] commitCiphertext =
          RecordCrypto.encryptSingleBody(keys, commitId, RecordRole.COMMIT, commitPlaintext);
      assertArrayEquals(bytes(vector, "commitCiphertext"), commitCiphertext);
      assertArrayEquals(bytes(vector, "commitFrame"), frame(commitId, commitCiphertext));

      FileRecordLayout emptyLayout = FileRecordLayout.forLogicalSize(0);
      assertArrayEquals(
          bytes(vector, "emptyFileAad"),
          VaultEncoding.recordAssociatedData(
              keys.vaultId(), emptyFileId.bytes(), RecordRole.FILE.code(), 0, 0));
      byte[] emptyFileCiphertext =
          RecordCrypto.encryptFileChunk(keys, emptyFileId, emptyLayout, 0, new byte[0]);
      assertArrayEquals(bytes(vector, "emptyFileCiphertext"), emptyFileCiphertext);
      assertArrayEquals(bytes(vector, "emptyFileFrame"), frame(emptyFileId, emptyFileCiphertext));
      var emptyFileRef =
          new RecordRef(
              emptyFileId,
              VaultFormat.FIXED_HEADER_BYTES,
              emptyLayout.storedLength(),
              RecordRole.FILE);
      assertArrayEquals(bytes(vector, "emptyFileRef"), encodeRecordRef(emptyFileRef));

      verifySlots(vector, parsed, keys);
      assertArrayEquals(fixedHeader, FixedHeaderCodec.encode(parsed));
      assertArrayEquals(
          bytes(vector, "emptyVault"),
          concatenate(
              fixedHeader,
              frame(manifestId, manifestCiphertext),
              frame(commitId, commitCiphertext)));
    }
  }

  @Test
  void standardUnlockWorkflowAcceptsTheLiteralIndependentVault()
      throws IOException,
          VaultAlreadyOpenException,
          VaultAccessException,
          UnableToUnlockVaultException {
    Properties vector = loadVector();
    Path vault = temporaryDirectory.resolve("independent-empty.vltb");
    Files.write(vault, bytes(vector, "emptyVault"));

    try (var passphrase = SensitiveBytes.copyOf(bytes(vector, "passphraseHex"));
        var session = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(0, session.manifest().fileCount());
      assertEquals(0, session.manifest().liveLogicalFileBytes());
      assertTrue(session.manifest().entries().isEmpty());
    }
  }

  private static void verifySlots(
      Properties vector, UnverifiedFixedHeader parsed, com.vultbridge.crypto.VaultKeySet keys) {
    verifySlot(vector, parsed.slotA(), keys, "slot0Input", "slot0Tag");
    verifySlot(vector, parsed.slotB(), keys, "slot1Input", "slot1Tag");
    assertEquals(2, HeaderSlotAuthenticator.verifyAndOrder(parsed, keys).size());
  }

  private static void verifySlot(
      Properties vector,
      UnverifiedHeaderSlot slot,
      com.vultbridge.crypto.VaultKeySet keys,
      String inputProperty,
      String tagProperty) {
    byte[] input =
        VaultEncoding.slotMacInput(
            keys.vaultId(),
            slot.slotIndex(),
            slot.generation(),
            slot.commitRecordId(),
            slot.commitOffset(),
            slot.commitStoredLength());
    assertArrayEquals(bytes(vector, inputProperty), input);
    try (var headerKey = keys.copyHeaderMacKey()) {
      assertArrayEquals(bytes(vector, tagProperty), HmacSha256.authenticate(headerKey, input));
    }
  }

  private static void assertRecordKey(
      Properties vector,
      com.vultbridge.crypto.VaultKeySet keys,
      RecordId recordId,
      String expectedProperty) {
    try (var masterKey = keys.copyMasterVaultKey();
        var recordKey =
            V1KeyDerivation.deriveRecordKey(masterKey, keys.vaultId(), recordId.bytes())) {
      assertArrayEquals(bytes(vector, expectedProperty), recordKey.copy());
    }
  }

  private static byte[] frame(RecordId recordId, byte[] body) throws IOException {
    var output = new ByteArrayOutputStream();
    output.write(RecordFrameCodec.encodeHeader(new RecordFrameHeader(recordId, body.length)));
    output.write(body);
    return output.toByteArray();
  }

  private static byte[] concatenate(byte[]... values) throws IOException {
    var output = new ByteArrayOutputStream();
    for (byte[] value : values) {
      output.write(value);
    }
    return output.toByteArray();
  }

  private static byte[] encodeRecordRef(RecordRef reference) throws IOException {
    var output = new ByteArrayOutputStream();
    try (var generator = VaultCbor.FACTORY.createGenerator(output)) {
      VaultCbor.writeRecordRef(generator, reference);
    }
    return output.toByteArray();
  }

  private static Properties loadVector() throws IOException {
    var properties = new Properties();
    try (InputStream input = Phase3KnownAnswerVectorTest.class.getResourceAsStream(RESOURCE)) {
      if (input == null) {
        throw new IOException("Phase 3 vector resource is missing");
      }
      properties.load(input);
    }
    return properties;
  }

  private static byte[] bytes(Properties vector, String key) {
    return HEX.parseHex(vector.getProperty(key));
  }
}
