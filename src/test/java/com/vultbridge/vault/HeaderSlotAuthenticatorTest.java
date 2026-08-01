package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.CreatedVaultKeySet;
import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.crypto.V1KeyHierarchy;
import com.vultbridge.crypto.WrappedMasterKey;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies slot promotion, field authentication, and unsigned generation selection. */
class HeaderSlotAuthenticatorTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final byte[] COMMIT_A = HEX.parseHex("606162636465666768696a6b6c6d6e6f");
  private static final byte[] COMMIT_B = HEX.parseHex("707172737475767778797a7b7c7d7e7f");

  @Test
  void validSlotsAreReturnedByDescendingUnsignedGeneration() {
    try (var fixture = fixture(1, 2)) {
      List<AuthenticatedHeaderSlot> slots =
          HeaderSlotAuthenticator.verifyAndOrder(fixture.header, fixture.created.keys());

      assertEquals(2, slots.size());
      assertEquals(1, slots.get(0).slotIndex());
      assertEquals(2, slots.get(0).generation());
      assertEquals(0, slots.get(1).slotIndex());
      assertArrayEquals(COMMIT_A, slots.get(1).commitRecordId());
      assertThrows(UnsupportedOperationException.class, () -> slots.add(slots.get(0)));
    }
  }

  @Test
  void generationOrderingUsesUnsignedU64ComparisonAndStableTieBreak() {
    try (var unsigned = fixture(Long.MAX_VALUE, -1L);
        var tied = fixture(7, 7)) {
      var unsignedSlots =
          HeaderSlotAuthenticator.verifyAndOrder(unsigned.header, unsigned.created.keys());
      var tiedSlots = HeaderSlotAuthenticator.verifyAndOrder(tied.header, tied.created.keys());

      assertEquals(-1L, unsignedSlots.get(0).generation());
      assertEquals(1, unsignedSlots.get(0).slotIndex());
      assertEquals(0, tiedSlots.get(0).slotIndex());
      assertEquals(1, tiedSlots.get(1).slotIndex());
    }
  }

  @Test
  void oneInvalidSlotIsIgnoredAndTwoInvalidSlotsReturnNoCandidates() {
    try (var fixture = fixture(1, 2)) {
      UnverifiedHeaderSlot invalidA = mutateTag(fixture.header.slotA(), 0);
      var oneInvalid =
          new UnverifiedFixedHeader(
              fixture.header.wrappedMasterKey(), invalidA, fixture.header.slotB());
      var bothInvalid =
          new UnverifiedFixedHeader(
              fixture.header.wrappedMasterKey(), invalidA, mutateTag(fixture.header.slotB(), 0));

      var oneResult = HeaderSlotAuthenticator.verifyAndOrder(oneInvalid, fixture.created.keys());
      assertEquals(1, oneResult.size());
      assertEquals(1, oneResult.get(0).slotIndex());
      assertTrue(
          HeaderSlotAuthenticator.verifyAndOrder(bothInvalid, fixture.created.keys()).isEmpty());
    }
  }

  @Test
  void everyTagByteMutationIsRejected() {
    try (var fixture = fixture(1, 2)) {
      for (int index = 0; index < VaultFormat.HMAC_SHA256_BYTES; index++) {
        var changedHeader =
            new UnverifiedFixedHeader(
                fixture.header.wrappedMasterKey(),
                mutateTag(fixture.header.slotA(), index),
                mutateTag(fixture.header.slotB(), 0));
        assertTrue(
            HeaderSlotAuthenticator.verifyAndOrder(changedHeader, fixture.created.keys())
                .isEmpty());
      }
    }
  }

  @Test
  void mutationOfEveryAuthenticatedSlotFieldIsRejected() {
    try (var fixture = fixture(1, 2)) {
      UnverifiedHeaderSlot original = fixture.header.slotA();
      byte[] changedId = original.commitRecordId();
      changedId[0] ^= 1;
      List<UnverifiedHeaderSlot> mutations =
          List.of(
              new UnverifiedHeaderSlot(
                  1,
                  original.generation(),
                  original.commitRecordId(),
                  original.commitOffset(),
                  original.commitStoredLength(),
                  original.tag()),
              new UnverifiedHeaderSlot(
                  0,
                  original.generation() + 1,
                  original.commitRecordId(),
                  original.commitOffset(),
                  original.commitStoredLength(),
                  original.tag()),
              new UnverifiedHeaderSlot(
                  0,
                  original.generation(),
                  changedId,
                  original.commitOffset(),
                  original.commitStoredLength(),
                  original.tag()),
              new UnverifiedHeaderSlot(
                  0,
                  original.generation(),
                  original.commitRecordId(),
                  original.commitOffset() + 1,
                  original.commitStoredLength(),
                  original.tag()),
              new UnverifiedHeaderSlot(
                  0,
                  original.generation(),
                  original.commitRecordId(),
                  original.commitOffset(),
                  original.commitStoredLength() + 1,
                  original.tag()));

      for (UnverifiedHeaderSlot mutation : mutations) {
        UnverifiedFixedHeader changedHeader;
        if (mutation.slotIndex() == 0) {
          changedHeader =
              new UnverifiedFixedHeader(
                  fixture.header.wrappedMasterKey(),
                  mutation,
                  mutateTag(fixture.header.slotB(), 0));
        } else {
          // A slot-A tag copied to physical slot B must fail because slotIndex is authenticated.
          changedHeader =
              new UnverifiedFixedHeader(
                  fixture.header.wrappedMasterKey(),
                  mutateTag(fixture.header.slotA(), 0),
                  mutation);
        }
        assertTrue(
            HeaderSlotAuthenticator.verifyAndOrder(changedHeader, fixture.created.keys())
                .isEmpty());
      }
    }
  }

  @Test
  void keySetForDifferentVaultCannotAuthenticateSlots() {
    try (var first = fixture(1, 2);
        var second = fixture(1, 2)) {
      byte[] differentVaultId = second.created.wrappedMasterKey().vaultId();
      differentVaultId[0] ^= 1;
      WrappedMasterKey changedEnvelope =
          new WrappedMasterKey(
              differentVaultId,
              second.created.wrappedMasterKey().parameters(),
              second.created.wrappedMasterKey().kdfSalt(),
              second.created.wrappedMasterKey().wrapNonce(),
              second.created.wrappedMasterKey().wrappedKey());
      var changedHeader =
          new UnverifiedFixedHeader(changedEnvelope, second.header.slotA(), second.header.slotB());

      assertTrue(
          HeaderSlotAuthenticator.verifyAndOrder(changedHeader, first.created.keys()).isEmpty());
    }
  }

  private static Fixture fixture(long generationA, long generationB) {
    SensitiveBytes passphrase =
        PassphraseEncoding.encode("correct horse battery staple".toCharArray());
    CreatedVaultKeySet created;
    try {
      created = V1KeyHierarchy.create(passphrase);
    } finally {
      passphrase.close();
    }

    try (var headerKey = created.keys().copyHeaderMacKey()) {
      byte[] vaultId = created.wrappedMasterKey().vaultId();
      var slotA =
          HeaderSlotAuthenticator.createSlot(headerKey, vaultId, 0, generationA, COMMIT_A, 282, 64);
      var slotB =
          HeaderSlotAuthenticator.createSlot(headerKey, vaultId, 1, generationB, COMMIT_B, 370, 80);
      return new Fixture(
          created, new UnverifiedFixedHeader(created.wrappedMasterKey(), slotA, slotB));
    } catch (RuntimeException failure) {
      created.close();
      throw failure;
    }
  }

  private static UnverifiedHeaderSlot mutateTag(UnverifiedHeaderSlot original, int byteIndex) {
    byte[] changedTag = original.tag();
    changedTag[byteIndex] ^= 1;
    return new UnverifiedHeaderSlot(
        original.slotIndex(),
        original.generation(),
        original.commitRecordId(),
        original.commitOffset(),
        original.commitStoredLength(),
        changedTag);
  }

  /** Owns the sensitive deterministic key fixture used by one test. */
  private static final class Fixture implements AutoCloseable {
    private final CreatedVaultKeySet created;
    private final UnverifiedFixedHeader header;

    private Fixture(CreatedVaultKeySet created, UnverifiedFixedHeader header) {
      this.created = created;
      this.header = header;
    }

    @Override
    public void close() {
      created.close();
    }
  }
}
