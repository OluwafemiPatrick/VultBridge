package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.platform.VaultAccessException;
import com.vultbridge.platform.VaultAlreadyOpenException;
import com.vultbridge.platform.VaultSidecarLock;
import com.vultbridge.vault.FixedHeaderCodec;
import com.vultbridge.vault.HeaderSlotAuthenticator;
import com.vultbridge.vault.UnverifiedHeaderSlot;
import com.vultbridge.vault.VaultFormat;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies durable empty-vault creation, full unlock trust order, and session ownership. */
class VaultCreationAndUnlockTest {
  @TempDir Path temporaryDirectory;

  @Test
  void createsValidatesLocksClosesAndReopensAnEmptyVault() throws Exception {
    Path vault = temporaryDirectory.resolve("empty.vltb");
    try (var passphrase = passphrase();
        var created = VaultCreator.create(vault, passphrase)) {
      assertEquals(0, created.manifest().fileCount());
      assertTrue(Files.size(vault) > VaultFormat.FIXED_HEADER_BYTES);
      assertThrows(VaultAlreadyOpenException.class, () -> VaultUnlocker.open(vault, passphrase));
    }

    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(0, reopened.manifest().fileCount());
    }
  }

  @Test
  void wrongPassphraseUsesOnlyTheApprovedFailureAndReleasesTheLock() throws Exception {
    Path vault = temporaryDirectory.resolve("wrong-passphrase.vltb");
    try (var passphrase = passphrase();
        var ignored = VaultCreator.create(vault, passphrase)) {
      assertEquals(0, ignored.manifest().fileCount());
    }

    try (var wrong = PassphraseEncoding.encode("incorrect horse battery staple".toCharArray())) {
      var failure =
          assertThrows(UnableToUnlockVaultException.class, () -> VaultUnlocker.open(vault, wrong));
      assertEquals("Unable to unlock this vault", failure.getMessage());
      assertNull(failure.getCause());
    }
    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(0, reopened.manifest().fileCount());
    }
  }

  @Test
  void closeClearsMetadataAndIsIdempotent() throws Exception {
    Path vault = temporaryDirectory.resolve("close.vltb");
    VaultSession session;
    try (var passphrase = passphrase()) {
      session = VaultCreator.create(vault, passphrase);
    }
    assertFalse(session.isClosed());
    session.close();
    session.close();
    assertTrue(session.isClosed());
    assertThrows(IllegalStateException.class, session::manifest);
  }

  @Test
  void rejectsExistingAndSymbolicDestinationsWithoutChangingTargets() throws IOException {
    Path existing = temporaryDirectory.resolve("existing.vltb");
    Files.writeString(existing, "unchanged");
    try (var passphrase = passphrase()) {
      assertThrows(VaultAccessException.class, () -> VaultCreator.create(existing, passphrase));
    }
    assertEquals("unchanged", Files.readString(existing));

    Path target = temporaryDirectory.resolve("target");
    Files.writeString(target, "target-unchanged");
    Path symbolic = temporaryDirectory.resolve("symbolic.vltb");
    Files.createSymbolicLink(symbolic, target.getFileName());
    try (var passphrase = passphrase()) {
      assertThrows(VaultAccessException.class, () -> VaultCreator.create(symbolic, passphrase));
    }
    assertEquals("target-unchanged", Files.readString(target));
  }

  @Test
  void serviceBoundaryRejectsNonCanonicalVaultExtensionsWithoutCreatingFiles() {
    for (String invalidName :
        java.util.List.of("vault", "vault.VLTB", "vault.vltb.backup", ".vltb")) {
      Path invalid = temporaryDirectory.resolve(invalidName);
      try (var passphrase = passphrase()) {
        assertThrows(VaultAccessException.class, () -> VaultCreator.create(invalid, passphrase));
      }
      assertFalse(Files.exists(invalid));
      assertFalse(Files.exists(temporaryDirectory.resolve(invalidName + ".lock")));
    }
  }

  @Test
  void unlockRejectsARenamedNonVltbFileBeforeCreatingItsSidecar() throws Exception {
    Path canonical = temporaryDirectory.resolve("canonical.vltb");
    try (var passphrase = passphrase();
        var ignored = VaultCreator.create(canonical, passphrase)) {
      assertEquals(0, ignored.manifest().fileCount());
    }
    Path renamed = temporaryDirectory.resolve("renamed.data");
    Files.move(canonical, renamed);

    try (var passphrase = passphrase()) {
      assertThrows(VaultAccessException.class, () -> VaultUnlocker.open(renamed, passphrase));
    }
    assertFalse(Files.exists(temporaryDirectory.resolve("renamed.data.lock")));
  }

  @Test
  void failedCreationLeavesItsUncertainArtifactAndReleasesTheLock() throws Exception {
    Path vault = temporaryDirectory.resolve("incomplete.vltb");
    var unusablePassphrase = passphrase();
    unusablePassphrase.close();

    assertThrows(VaultAccessException.class, () -> VaultCreator.create(vault, unusablePassphrase));
    assertTrue(Files.isRegularFile(vault));
    try (var lock = VaultSidecarLock.acquire(vault)) {
      assertTrue(lock.isOpen());
    }
  }

  @Test
  void invalidNewerCommitCandidateFallsBackToThePriorAuthenticatedSlot() throws Exception {
    Path vault = temporaryDirectory.resolve("fallback.vltb");
    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      byte[] vaultId = session.keys().vaultId();
      try (var headerKey = session.keys().copyHeaderMacKey()) {
        byte[] invalidCommitId = new byte[VaultFormat.RECORD_ID_BYTES];
        invalidCommitId[0] = 99;
        UnverifiedHeaderSlot invalidNewer =
            HeaderSlotAuthenticator.createSlot(
                headerKey, vaultId, 1, 2, invalidCommitId, session.channel().size() + 100, 80);
        writeFully(
            session.channel(),
            VaultFormat.HEADER_SLOT_B_OFFSET,
            FixedHeaderCodec.encodeSlot(invalidNewer));
        session.channel().force(true);
      }
    }

    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(0, reopened.manifest().fileCount());
    }
  }

  @Test
  void unsignedCommitRangeOutsideJavaFileApisFallsBackToThePriorSlot() throws Exception {
    Path vault = temporaryDirectory.resolve("unsigned-fallback.vltb");
    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      byte[] vaultId = session.keys().vaultId();
      try (var headerKey = session.keys().copyHeaderMacKey()) {
        UnverifiedHeaderSlot invalidNewer =
            HeaderSlotAuthenticator.createSlot(
                headerKey, vaultId, 1, 2, new byte[VaultFormat.RECORD_ID_BYTES], -1L, 80);
        writeFully(
            session.channel(),
            VaultFormat.HEADER_SLOT_B_OFFSET,
            FixedHeaderCodec.encodeSlot(invalidNewer));
        session.channel().force(true);
      }
    }

    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(0, reopened.manifest().fileCount());
    }
  }

  @Test
  void twoInvalidSlotTagsFailWithoutMetadata() throws Exception {
    Path vault = temporaryDirectory.resolve("invalid-slots.vltb");
    try (var passphrase = passphrase();
        var ignored = VaultCreator.create(vault, passphrase)) {
      assertEquals(0, ignored.manifest().fileCount());
    }
    try (var channel = FileChannel.open(vault, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
      mutateByte(channel, VaultFormat.HEADER_SLOT_A_OFFSET + VaultFormat.HEADER_SLOT_BYTES - 1L);
      mutateByte(channel, VaultFormat.HEADER_SLOT_B_OFFSET + VaultFormat.HEADER_SLOT_BYTES - 1L);
      channel.force(true);
    }
    try (var passphrase = passphrase()) {
      assertThrows(UnableToUnlockVaultException.class, () -> VaultUnlocker.open(vault, passphrase));
    }
  }

  @Test
  void anotherJvmCannotAcquireTheSessionLock() throws Exception {
    Path vault = temporaryDirectory.resolve("process-lock.vltb");
    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      assertEquals(0, session.manifest().fileCount());
      assertEquals("process-lock.vltb", session.vaultDisplayName());
      Process process =
          new ProcessBuilder(
                  Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                  "-cp",
                  System.getProperty("java.class.path"),
                  "com.vultbridge.service.SidecarLockProbe",
                  vault.toString())
              .start();
      int exitCode = process.waitFor();
      String processError =
          new String(
              process.getErrorStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
      assertEquals(2, exitCode, processError);
    }
  }

  private static void writeFully(FileChannel channel, long offset, byte[] bytes)
      throws IOException {
    var buffer = java.nio.ByteBuffer.wrap(bytes);
    while (buffer.hasRemaining()) {
      int written = channel.write(buffer, offset + buffer.position());
      if (written <= 0) {
        throw new IOException("Unable to write test fixture");
      }
    }
  }

  private static void mutateByte(FileChannel channel, long offset) throws IOException {
    var value = java.nio.ByteBuffer.allocate(1);
    if (channel.read(value, offset) != 1) {
      throw new IOException("Unable to read test fixture byte");
    }
    value.array()[0] ^= 1;
    writeFully(channel, offset, value.array());
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return PassphraseEncoding.encode("correct horse battery staple".toCharArray());
  }
}
