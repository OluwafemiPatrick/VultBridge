package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies the metadata-only application service across the complete Phase 4 workflow. */
class VaultServiceTest {
  @TempDir Path temporaryDirectory;

  @Test
  void ownsCreateImportExportDeleteAndLockWithoutExposingSession() throws Exception {
    Path vault = temporaryDirectory.resolve("service.vltb");
    Path source = temporaryDirectory.resolve("service-source.bin");
    Path output = temporaryDirectory.resolve("service-output.bin");
    byte[] original = {4, 3, 2, 1};
    Files.write(source, original);
    var control = new NeverCancelledControl();

    try (var service = new VaultService();
        var passphrase = passphrase()) {
      VaultSnapshot created = service.create(vault, passphrase);
      assertEquals("service.vltb", created.vaultDisplayName());
      assertTrue(service.isOpen());

      VaultSnapshot imported = service.importFiles(List.of(source), control);
      assertEquals(1, imported.manifest().fileCount());

      VaultSnapshot exported = service.export("service-source.bin", output, control);
      assertEquals(1, exported.manifest().fileCount());
      assertArrayEquals(original, Files.readAllBytes(output));

      VaultSnapshot deleted = service.delete("service-source.bin", control);
      assertEquals(0, deleted.manifest().fileCount());
      service.lock();
      assertFalse(service.isOpen());
    }

    try (var service = new VaultService();
        var passphrase = passphrase()) {
      assertEquals(0, service.open(vault, passphrase).manifest().fileCount());
    }
  }

  @Test
  void wrongPassphraseBecomesOnlyTheApprovedFailureCategory() throws Exception {
    Path vault = temporaryDirectory.resolve("wrong-service.vltb");
    try (var service = new VaultService();
        var passphrase = passphrase()) {
      service.create(vault, passphrase);
    }

    try (var service = new VaultService();
        var wrong = PassphraseEncoding.encode("incorrect horse battery staple".toCharArray())) {
      VaultOperationException failure =
          assertThrows(VaultOperationException.class, () -> service.open(vault, wrong));
      assertEquals(JobFailureCategory.UNABLE_TO_UNLOCK, failure.category());
      assertEquals(null, failure.getMessage());
      assertFalse(service.isOpen());
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
