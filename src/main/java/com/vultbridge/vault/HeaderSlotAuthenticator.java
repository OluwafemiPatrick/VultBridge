package com.vultbridge.vault;

import com.vultbridge.crypto.HmacSha256;
import com.vultbridge.crypto.SensitiveBytes;
import com.vultbridge.crypto.VaultKeySet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Creates header-slot tags and promotes structurally parsed slots only after HMAC verification.
 *
 * <p>Verification requires an unlocked {@link VaultKeySet}, preventing a parsed slot from being
 * treated as trusted based on structure alone. Valid slots are returned by descending unsigned
 * generation, with physical slot index as a deterministic tie-breaker. Commit references remain
 * unvalidated until Phase 3.
 */
public final class HeaderSlotAuthenticator {
  private HeaderSlotAuthenticator() {}

  /** Creates an encoded-slot model with a tag covering every canonical slot field. */
  public static UnverifiedHeaderSlot createSlot(
      SensitiveBytes headerMacKey,
      byte[] vaultId,
      int slotIndex,
      long generation,
      byte[] commitRecordId,
      long commitOffset,
      long commitStoredLength) {
    Objects.requireNonNull(headerMacKey, "headerMacKey");
    byte[] input =
        VaultEncoding.slotMacInput(
            vaultId, slotIndex, generation, commitRecordId, commitOffset, commitStoredLength);
    byte[] tag = HmacSha256.authenticate(headerMacKey, input);
    return new UnverifiedHeaderSlot(
        slotIndex, generation, commitRecordId, commitOffset, commitStoredLength, tag);
  }

  /** Verifies both physical slots and returns only authenticated values in selection order. */
  public static List<AuthenticatedHeaderSlot> verifyAndOrder(
      UnverifiedFixedHeader header, VaultKeySet unlockedKeys) {
    Objects.requireNonNull(header, "header");
    Objects.requireNonNull(unlockedKeys, "unlockedKeys");
    byte[] vaultId = header.wrappedMasterKey().vaultId();
    if (!Arrays.equals(vaultId, unlockedKeys.vaultId())) {
      return List.of();
    }

    var authenticated = new ArrayList<AuthenticatedHeaderSlot>(2);
    try (var headerMacKey = unlockedKeys.copyHeaderMacKey()) {
      verifySlot(header.slotA(), vaultId, headerMacKey).ifPresent(authenticated::add);
      verifySlot(header.slotB(), vaultId, headerMacKey).ifPresent(authenticated::add);
    }
    // Natural signed ordering is not valid for the u64 generation field; reverse with an explicit
    // unsigned comparison while preserving ascending physical index for equal generations.
    authenticated.sort(
        (left, right) -> {
          int generationOrder = Long.compareUnsigned(right.generation(), left.generation());
          return generationOrder != 0
              ? generationOrder
              : Integer.compare(left.slotIndex(), right.slotIndex());
        });
    return List.copyOf(authenticated);
  }

  /**
   * Verifies one slot tag and promotes it to authenticated state when the tag is valid.
   *
   * <p>This is used after a newly written mutation slot has been forced; callers must not update
   * session state before durable installation has succeeded.
   */
  public static java.util.Optional<AuthenticatedHeaderSlot> verifySlot(
      UnverifiedHeaderSlot slot, byte[] vaultId, SensitiveBytes headerMacKey) {
    Objects.requireNonNull(slot, "slot");
    Objects.requireNonNull(vaultId, "vaultId");
    Objects.requireNonNull(headerMacKey, "headerMacKey");
    byte[] input =
        VaultEncoding.slotMacInput(
            vaultId,
            slot.slotIndex(),
            slot.generation(),
            slot.commitRecordId(),
            slot.commitOffset(),
            slot.commitStoredLength());
    if (!HmacSha256.verify(headerMacKey, input, slot.tag())) {
      return java.util.Optional.empty();
    }
    return java.util.Optional.of(new AuthenticatedHeaderSlot(slot));
  }
}
