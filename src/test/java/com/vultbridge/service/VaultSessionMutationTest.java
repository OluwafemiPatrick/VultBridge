package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.vault.AuthenticatedHeaderSlot;
import com.vultbridge.vault.HeaderSlotAuthenticator;
import com.vultbridge.vault.UnverifiedHeaderSlot;
import com.vultbridge.vault.VaultManifest;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies atomic advancement of authenticated metadata and active-slot session state. */
class VaultSessionMutationTest {
  @TempDir Path temporaryDirectory;

  @Test
  void advancesManifestAndSlotTogether() throws Exception {
    try (var passphrase = passphrase();
        var session = VaultCreator.create(temporaryDirectory.resolve("advance.vltb"), passphrase)) {
      var nextManifest = new VaultManifest(List.of());
      var nextSlot = nextSlot(session, 1 - session.activeSlot().slotIndex(), 1);

      session.installCommittedState(nextManifest, nextSlot);

      assertSame(nextManifest, session.manifest());
      assertSame(nextSlot, session.activeSlot());
    }
  }

  @Test
  void rejectedTransitionRetainsBothPreviousValues() throws Exception {
    try (var passphrase = passphrase();
        var session = VaultCreator.create(temporaryDirectory.resolve("retain.vltb"), passphrase)) {
      var originalManifest = session.manifest();
      var originalSlot = session.activeSlot();
      var invalidSlot = nextSlot(session, originalSlot.slotIndex(), 1);

      assertThrows(
          IllegalArgumentException.class,
          () -> session.installCommittedState(new VaultManifest(List.of()), invalidSlot));

      assertSame(originalManifest, session.manifest());
      assertSame(originalSlot, session.activeSlot());
    }
  }

  private static AuthenticatedHeaderSlot nextSlot(
      VaultSession session, int index, long generationIncrement) {
    var active = session.activeSlot();
    byte[] vaultId = session.keys().vaultId();
    try (var headerKey = session.keys().copyHeaderMacKey()) {
      UnverifiedHeaderSlot slot =
          HeaderSlotAuthenticator.createSlot(
              headerKey,
              vaultId,
              index,
              active.generation() + generationIncrement,
              active.commitRecordId(),
              active.commitOffset(),
              active.commitStoredLength());
      return HeaderSlotAuthenticator.verifySlot(slot, vaultId, headerKey).orElseThrow();
    }
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return PassphraseEncoding.encode("correct horse battery staple".toCharArray());
  }
}
