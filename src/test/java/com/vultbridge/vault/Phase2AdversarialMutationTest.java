package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.Argon2idKdf;
import com.vultbridge.crypto.Argon2idParameters;
import com.vultbridge.crypto.AuthenticationFailedException;
import com.vultbridge.crypto.ChaCha20Poly1305;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.crypto.V1KeyDerivation;
import com.vultbridge.crypto.V1KeyHierarchy;
import com.vultbridge.crypto.VaultKeySet;
import com.vultbridge.crypto.WrappedMasterKey;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Exercises every fixed-header byte through the Phase 2 structural and authentication boundaries.
 *
 * <p>Immutable mutations must either fail structural parsing or fail wrapped-key authentication.
 * Slot mutations must either fail structural parsing or remain unpromoted when the other fallback
 * slot is deliberately invalidated. Consequently, no unauthenticated commit reference—and no future
 * item metadata reachable through one—crosses the Phase 2 trust boundary.
 */
class Phase2AdversarialMutationTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final byte[] PASSPHRASE =
      HEX.parseHex("636f727265637420686f727365206261747465727920737461706c65");
  private static final int IMMUTABLE_END =
      VaultFormat.PRELUDE_BYTES + VaultFormat.IMMUTABLE_HEADER_BYTES;
  private static final int SLOT_A_START = IMMUTABLE_END;
  private static final int SLOT_B_START = SLOT_A_START + VaultFormat.HEADER_SLOT_BYTES;

  @Test
  void wrongPassphraseFailsBeforeAnySlotCanBeAuthenticated() throws HeaderParsingException {
    byte[] headerBytes = createHeaderFixture();
    UnverifiedFixedHeader parsed = FixedHeaderCodec.parse(headerBytes);

    try (var wrongPassphrase =
        SensitiveBytes.copyOf(
            HEX.parseHex("696e636f727265637420686f727365206261747465727920737461706c65"))) {
      assertThrows(
          AuthenticationFailedException.class,
          () -> V1KeyHierarchy.unwrapKeySet(wrongPassphrase, parsed.wrappedMasterKey()));
    }
  }

  @Test
  void everyPreludeAndImmutableHeaderByteMutationFailsBeforeSlotPromotion() {
    byte[] original = createHeaderFixture();
    try (var passphrase = SensitiveBytes.copyOf(PASSPHRASE)) {
      for (int offset = 0; offset < IMMUTABLE_END; offset++) {
        byte[] changed = mutate(original, offset);
        try {
          UnverifiedFixedHeader parsed = FixedHeaderCodec.parse(changed);
          int mutatedOffset = offset;
          assertThrows(
              AuthenticationFailedException.class,
              () -> V1KeyHierarchy.unwrapKeySet(passphrase, parsed.wrappedMasterKey()),
              () -> "immutable mutation authenticated at byte " + mutatedOffset);
        } catch (HeaderParsingException expected) {
          // Structural rejection is the required outcome for prelude, algorithm, and bound errors.
        }
      }
    }
  }

  @Test
  void everySlotByteMutationIsRejectedOrRemainsUnauthenticated()
      throws HeaderParsingException, AuthenticationFailedException {
    byte[] original = createHeaderFixture();
    UnverifiedFixedHeader originalHeader = FixedHeaderCodec.parse(original);
    try (var passphrase = SensitiveBytes.copyOf(PASSPHRASE);
        var keys = V1KeyHierarchy.unwrapKeySet(passphrase, originalHeader.wrappedMasterKey())) {
      assertEverySlotMutationUntrusted(original, SLOT_A_START, SLOT_B_START, keys);
      assertEverySlotMutationUntrusted(original, SLOT_B_START, SLOT_A_START, keys);
    }
  }

  private static void assertEverySlotMutationUntrusted(
      byte[] original, int targetSlotStart, int fallbackSlotStart, VaultKeySet keys) {
    int fallbackTagLastByte = fallbackSlotStart + VaultFormat.HEADER_SLOT_BYTES - 1;
    for (int relativeOffset = 0; relativeOffset < VaultFormat.HEADER_SLOT_BYTES; relativeOffset++) {
      byte[] changed = mutate(original, fallbackTagLastByte);
      changed[targetSlotStart + relativeOffset] ^= 1;
      try {
        UnverifiedFixedHeader parsed = FixedHeaderCodec.parse(changed);
        int mutatedOffset = targetSlotStart + relativeOffset;
        assertTrue(
            HeaderSlotAuthenticator.verifyAndOrder(parsed, keys).isEmpty(),
            () -> "slot mutation authenticated at byte " + mutatedOffset);
      } catch (HeaderParsingException expected) {
        // Slot-index and reserved-byte mutations are rejected before authentication.
      }
    }
  }

  private static byte[] createHeaderFixture() {
    byte[] vaultId = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
    byte[] salt = HEX.parseHex("101112131415161718191a1b1c1d1e1f");
    byte[] nonce = HEX.parseHex("202122232425262728292a2b");
    var parameters = new Argon2idParameters(VaultFormat.ARGON2_MIN_MEMORY_KIB, 1, 1);

    try (var passphrase = SensitiveBytes.copyOf(PASSPHRASE);
        var masterKey =
            SensitiveBytes.copyOf(
                HEX.parseHex(
                    "303132333435363738393a3b3c3d3e3f" + "404142434445464748494a4b4c4d4e4f"));
        var kek = Argon2idKdf.derive(passphrase, salt, parameters);
        var headerKey = V1KeyDerivation.deriveHeaderMacKey(masterKey, vaultId)) {
      byte[] prefix =
          VaultEncoding.immutableHeaderPrefix(
              vaultId,
              VaultFormat.KDF_ID_ARGON2ID,
              VaultFormat.ARGON2_VERSION_13,
              parameters.memoryKiB(),
              parameters.iterations(),
              parameters.parallelism(),
              salt,
              nonce);
      byte[] masterKeyCopy = masterKey.copy();
      byte[] wrapped;
      try {
        wrapped =
            ChaCha20Poly1305.encrypt(
                kek, nonce, masterKeyCopy, VaultEncoding.headerWrapAssociatedData(prefix));
      } finally {
        Arrays.fill(masterKeyCopy, (byte) 0);
      }
      var envelope = new WrappedMasterKey(vaultId, parameters, salt, nonce, wrapped);
      var slotA =
          HeaderSlotAuthenticator.createSlot(
              headerKey,
              vaultId,
              0,
              1,
              HEX.parseHex("606162636465666768696a6b6c6d6e6f"),
              VaultFormat.FIXED_HEADER_BYTES,
              64);
      var slotB =
          HeaderSlotAuthenticator.createSlot(
              headerKey,
              vaultId,
              1,
              2,
              HEX.parseHex("707172737475767778797a7b7c7d7e7f"),
              VaultFormat.FIXED_HEADER_BYTES + VaultFormat.RECORD_FRAME_HEADER_BYTES + 64L,
              80);
      return FixedHeaderCodec.encode(new UnverifiedFixedHeader(envelope, slotA, slotB));
    }
  }

  private static byte[] mutate(byte[] original, int offset) {
    byte[] changed = Arrays.copyOf(original, original.length);
    changed[offset] ^= 1;
    return changed;
  }
}
