package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies persistent logical deletion without physical-vault shrinkage. */
class VaultDeleterTest {
  @TempDir Path temporaryDirectory;

  @Test
  void deletionPersistsAfterReopenAndDoesNotShrinkTheVault() throws Exception {
    Path vault = temporaryDirectory.resolve("delete.vltb");
    Path source = temporaryDirectory.resolve("remove.bin");
    Files.write(source, new byte[] {1, 2, 3});
    long beforeDelete;
    long afterDelete;

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultImporter.importFiles(session, List.of(source), new NeverCancelledControl());
      beforeDelete = session.snapshot().physicalVaultBytes();

      VaultSnapshot deleted =
          VaultDeleter.delete(session, "remove.bin", new NeverCancelledControl());

      afterDelete = deleted.physicalVaultBytes();
      assertEquals(0, deleted.manifest().fileCount());
      assertTrue(afterDelete > beforeDelete);
    }

    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(0, reopened.manifest().fileCount());
      assertEquals(afterDelete, reopened.snapshot().physicalVaultBytes());
    }
  }

  @Test
  void rejectsMissingSelectionWithoutChangingState() throws Exception {
    Path vault = temporaryDirectory.resolve("missing.vltb");
    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      var originalSlot = session.activeSlot();
      VaultOperationException failure =
          assertThrows(
              VaultOperationException.class,
              () -> VaultDeleter.delete(session, "absent.bin", new NeverCancelledControl()));

      assertEquals(JobFailureCategory.INPUT_REJECTED, failure.category());
      assertEquals(0, session.manifest().fileCount());
      assertEquals(originalSlot.generation(), session.activeSlot().generation());
    }
  }

  private static final class NeverCancelledControl implements VaultOperationControl {
    @Override
    public boolean isCancellationRequested() {
      return false;
    }

    @Override
    public void checkpoint() {}

    @Override
    public void reportProgress(JobProgress progress) {}
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return PassphraseEncoding.encode("correct horse battery staple".toCharArray());
  }
}
