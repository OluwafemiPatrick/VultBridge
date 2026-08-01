package com.vultbridge.service;

import com.vultbridge.vault.AppendCommitProtocol;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.VaultManifest;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * Logically removes one selected entry through an authenticated manifest mutation.
 *
 * <p>Deletion appends a replacement MANIFEST and COMMIT; it never truncates the vault or claims to
 * securely erase the old FILE ciphertext. Display names are accepted only as the unique
 * authenticated selection key and are never included in failures or logs.
 */
public final class VaultDeleter {
  private VaultDeleter() {}

  /** Removes the uniquely named current entry and returns the resulting metadata snapshot. */
  public static VaultSnapshot delete(
      VaultSession session, String selectedDisplayName, VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    Objects.requireNonNull(session, "session");
    Objects.requireNonNull(selectedDisplayName, "selectedDisplayName");
    Objects.requireNonNull(control, "control");
    control.checkpoint();

    List<ManifestEntry> remaining =
        session.manifest().entries().stream()
            .filter(entry -> !entry.displayName().equals(selectedDisplayName))
            .toList();
    if (remaining.size() != session.manifest().fileCount() - 1) {
      throw new VaultOperationException(JobFailureCategory.INPUT_REJECTED);
    }
    try {
      return VaultMutationWriter.commit(
          session,
          AppendCommitProtocol.forMutation(session.channel(), session.activeSlot()),
          new VaultManifest(remaining),
          control);
    } catch (IOException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    }
  }
}
