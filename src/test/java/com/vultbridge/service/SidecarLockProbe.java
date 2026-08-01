package com.vultbridge.service;

import com.vultbridge.platform.VaultAlreadyOpenException;
import com.vultbridge.platform.VaultSidecarLock;
import java.nio.file.Path;

/** Separate-JVM test probe for operating-system sidecar lock contention. */
public final class SidecarLockProbe {
  private SidecarLockProbe() {}

  /** Exits with status 2 when another process already owns the requested vault lock. */
  public static void main(String[] arguments) throws Exception {
    try (var lock = VaultSidecarLock.acquire(Path.of(arguments[0]))) {
      System.exit(lock.isOpen() ? 0 : 3);
    } catch (VaultAlreadyOpenException expected) {
      System.exit(2);
    }
  }
}
