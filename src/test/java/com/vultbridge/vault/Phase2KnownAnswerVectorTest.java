package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.vultbridge.crypto.Argon2idKdf;
import com.vultbridge.crypto.Argon2idParameters;
import com.vultbridge.crypto.AuthenticationFailedException;
import com.vultbridge.crypto.ChaCha20Poly1305;
import com.vultbridge.crypto.HmacSha256;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.crypto.V1KeyDerivation;
import com.vultbridge.crypto.V1KeyHierarchy;
import java.io.IOException;
import java.io.InputStream;
import java.util.HexFormat;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/**
 * Verifies the complete Phase 2 pipeline against one immutable vector produced by independent
 * tools.
 */
class Phase2KnownAnswerVectorTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final String RESOURCE = "/com/vultbridge/vectors/v1-phase2.properties";

  @Test
  void everyPhase2ArtifactMatchesTheIndependentVector()
      throws IOException, HeaderParsingException, AuthenticationFailedException {
    Properties vector = loadVector();
    byte[] vaultId = bytes(vector, "vaultId");
    byte[] salt = bytes(vector, "kdfSalt");
    byte[] nonce = bytes(vector, "wrapNonce");
    byte[] recordId = bytes(vector, "recordId");
    var parameters =
        new Argon2idParameters(
            integer(vector, "argonMemoryKiB"),
            integer(vector, "argonIterations"),
            integer(vector, "argonParallelism"));

    try (var passphrase = SensitiveBytes.copyOf(bytes(vector, "passphraseHex"));
        var kek = Argon2idKdf.derive(passphrase, salt, parameters);
        var masterKey = SensitiveBytes.copyOf(bytes(vector, "masterVaultKey"));
        var headerKey = V1KeyDerivation.deriveHeaderMacKey(masterKey, vaultId);
        var recordKey = V1KeyDerivation.deriveRecordKey(masterKey, vaultId, recordId)) {
      assertArrayEquals(bytes(vector, "derivedKek"), kek.copy());

      byte[] immutablePrefix =
          VaultEncoding.immutableHeaderPrefix(
              vaultId,
              VaultFormat.KDF_ID_ARGON2ID,
              VaultFormat.ARGON2_VERSION_13,
              parameters.memoryKiB(),
              parameters.iterations(),
              parameters.parallelism(),
              salt,
              nonce);
      byte[] headerWrapAd = VaultEncoding.headerWrapAssociatedData(immutablePrefix);
      assertArrayEquals(bytes(vector, "headerWrapAd"), headerWrapAd);
      byte[] masterKeyCopy = masterKey.copy();
      try {
        assertArrayEquals(
            bytes(vector, "wrappedMasterVaultKey"),
            ChaCha20Poly1305.encrypt(kek, nonce, masterKeyCopy, headerWrapAd));
      } finally {
        java.util.Arrays.fill(masterKeyCopy, (byte) 0);
      }
      assertArrayEquals(bytes(vector, "headerMacKey"), headerKey.copy());
      assertArrayEquals(bytes(vector, "recordKey"), recordKey.copy());

      byte[] recordAad =
          VaultEncoding.recordAssociatedData(
              vaultId, recordId, VaultFormat.ROLE_FILE, 0x0102_0304L, 0x0040_0000L);
      assertArrayEquals(bytes(vector, "recordAad"), recordAad);
      assertArrayEquals(
          bytes(vector, "fileChunkNonce"), VaultEncoding.fileChunkNonce(0x0102_0304L));

      UnverifiedHeaderSlot slotA =
          verifySlotVector(
              vector, headerKey, vaultId, 0, 1, "slot0CommitId", 282, 64, "slot0Input", "slot0Tag");
      UnverifiedHeaderSlot slotB =
          verifySlotVector(
              vector, headerKey, vaultId, 1, 2, "slot1CommitId", 370, 80, "slot1Input", "slot1Tag");
      var envelope =
          new com.vultbridge.crypto.WrappedMasterKey(
              vaultId, parameters, salt, nonce, bytes(vector, "wrappedMasterVaultKey"));
      byte[] fixedHeader =
          FixedHeaderCodec.encode(new UnverifiedFixedHeader(envelope, slotA, slotB));
      assertArrayEquals(bytes(vector, "fixedHeader"), fixedHeader);
      assertArrayEquals(fixedHeader, FixedHeaderCodec.encode(FixedHeaderCodec.parse(fixedHeader)));
    }
  }

  @Test
  void literalHeaderFollowsTheCompletePhase2TrustOrder()
      throws IOException, HeaderParsingException, AuthenticationFailedException {
    Properties vector = loadVector();
    UnverifiedFixedHeader parsed = FixedHeaderCodec.parse(bytes(vector, "fixedHeader"));

    try (var passphrase = SensitiveBytes.copyOf(bytes(vector, "passphraseHex"));
        var keys = V1KeyHierarchy.unwrapKeySet(passphrase, parsed.wrappedMasterKey())) {
      var authenticatedSlots = HeaderSlotAuthenticator.verifyAndOrder(parsed, keys);

      assertEquals(2, authenticatedSlots.size());
      assertEquals(1, authenticatedSlots.get(0).slotIndex());
      assertEquals(2, authenticatedSlots.get(0).generation());
      assertEquals(0, authenticatedSlots.get(1).slotIndex());
      assertEquals(1, authenticatedSlots.get(1).generation());
    }
  }

  private static UnverifiedHeaderSlot verifySlotVector(
      Properties vector,
      SensitiveBytes headerKey,
      byte[] vaultId,
      int slotIndex,
      long generation,
      String commitIdProperty,
      long commitOffset,
      long commitLength,
      String inputProperty,
      String tagProperty) {
    byte[] commitId = bytes(vector, commitIdProperty);
    byte[] input =
        VaultEncoding.slotMacInput(
            vaultId, slotIndex, generation, commitId, commitOffset, commitLength);
    assertArrayEquals(bytes(vector, inputProperty), input);
    assertArrayEquals(bytes(vector, tagProperty), HmacSha256.authenticate(headerKey, input));
    return new UnverifiedHeaderSlot(
        slotIndex, generation, commitId, commitOffset, commitLength, bytes(vector, tagProperty));
  }

  private static Properties loadVector() throws IOException {
    var properties = new Properties();
    try (InputStream input = Phase2KnownAnswerVectorTest.class.getResourceAsStream(RESOURCE)) {
      if (input == null) {
        throw new IOException("Phase 2 vector resource is missing");
      }
      properties.load(input);
    }
    return properties;
  }

  private static byte[] bytes(Properties vector, String key) {
    return HEX.parseHex(vector.getProperty(key));
  }

  private static int integer(Properties vector, String key) {
    return Integer.parseInt(vector.getProperty(key));
  }
}
