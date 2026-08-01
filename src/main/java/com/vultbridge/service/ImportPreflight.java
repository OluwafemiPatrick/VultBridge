package com.vultbridge.service;

import com.vultbridge.platform.SourceFileSnapshot;
import com.vultbridge.vault.FileRecordLayout;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.VaultFormat;
import com.vultbridge.vault.VaultManifest;
import java.util.Objects;

/**
 * Validates one import candidate before any bytes are appended to the vault.
 *
 * <p>The preflight enforces the canonical manifest name policy, case-sensitive uniqueness, shared
 * file-count and live-byte limits, and checked arithmetic using caller-inspected no-follow source
 * facts. Its result deliberately omits the host path and file contents.
 */
final class ImportPreflight {
  private ImportPreflight() {}

  static ValidatedImport validate(
      VaultManifest manifest, String displayName, SourceFileSnapshot snapshot)
      throws VaultOperationException {
    Objects.requireNonNull(manifest, "manifest");
    Objects.requireNonNull(snapshot, "snapshot");
    try {
      ManifestEntry.requireValidDisplayName(displayName);
      if (manifest.fileCount() >= VaultFormat.MAXIMUM_FILE_COUNT
          || manifest.entries().stream()
              .anyMatch(entry -> entry.displayName().equals(displayName))) {
        throw rejected();
      }
      long nextLiveBytes = Math.addExact(manifest.liveLogicalFileBytes(), snapshot.size());
      if (nextLiveBytes > VaultFormat.MAXIMUM_LIVE_FILE_BYTES) {
        throw rejected();
      }
      return new ValidatedImport(displayName, FileRecordLayout.forLogicalSize(snapshot.size()));
    } catch (IllegalArgumentException | ArithmeticException exception) {
      throw rejected();
    }
  }

  private static VaultOperationException rejected() {
    return new VaultOperationException(JobFailureCategory.INPUT_REJECTED);
  }

  /** Holds the validated, path-free facts needed to append one import candidate. */
  record ValidatedImport(String displayName, FileRecordLayout layout) {
    ValidatedImport {
      Objects.requireNonNull(displayName, "displayName");
      Objects.requireNonNull(layout, "layout");
    }
  }
}
