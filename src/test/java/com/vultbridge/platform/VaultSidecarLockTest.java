package com.vultbridge.platform;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies sidecar contention, no-follow behavior, persistence, and idempotent cleanup. */
class VaultSidecarLockTest {
  @TempDir Path temporaryDirectory;

  @Test
  void retainsExclusiveLockUntilIdempotentClose() throws Exception {
    Path vault = temporaryDirectory.resolve("vault.vltb");
    Path sidecar = temporaryDirectory.resolve("vault.vltb.lock");
    var first = VaultSidecarLock.acquire(vault);
    assertTrue(first.isOpen());
    assertTrue(Files.isRegularFile(sidecar));
    assertThrows(VaultAlreadyOpenException.class, () -> VaultSidecarLock.acquire(vault));

    first.close();
    first.close();
    assertFalse(first.isOpen());
    assertTrue(Files.exists(sidecar));

    try (var second = VaultSidecarLock.acquire(vault)) {
      assertTrue(second.isOpen());
    }
  }

  @Test
  void rejectsASymbolicLinkSidecarWithoutModifyingItsTarget() throws IOException {
    Path vault = temporaryDirectory.resolve("vault.vltb");
    Path target = temporaryDirectory.resolve("target");
    Files.writeString(target, "unchanged");
    Files.createSymbolicLink(temporaryDirectory.resolve("vault.vltb.lock"), target.getFileName());

    assertThrows(VaultAccessException.class, () -> VaultSidecarLock.acquire(vault));
    assertTrue(Files.readString(target).equals("unchanged"));
  }

  @Test
  void filesystemPolicyAcceptsOnlyTheCurrentlyVerifiedType() {
    assertTrue(VaultSidecarLock.isSupportedFileStoreType("apfs"));
    assertTrue(VaultSidecarLock.isSupportedFileStoreType("APFS"));
    for (String unsupported :
        java.util.List.of("ext4", "nfs", "smbfs", "webdav", "fuse", "fuse.vendor")) {
      assertFalse(VaultSidecarLock.isSupportedFileStoreType(unsupported));
    }
    assertFalse(VaultSidecarLock.isSupportedFileStoreType(null));
  }
}
