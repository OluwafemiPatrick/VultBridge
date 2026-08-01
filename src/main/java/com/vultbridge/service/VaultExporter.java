package com.vultbridge.service;

import com.vultbridge.platform.ExportFileTarget;
import com.vultbridge.vault.FileRecordReader;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.VaultDataException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Authentically exports one selected vault entry to a new ordinary host file.
 *
 * <p>The selected metadata comes from the current authenticated manifest. Plaintext flows only from
 * the bounded FILE reader into a create-new temporary output, which is published after force and
 * close without overwriting. The operation does not modify the vault, auto-open the result, or
 * retain destination history.
 */
public final class VaultExporter {
  private VaultExporter() {}

  /** Exports the uniquely named current entry to a new explicit destination. */
  public static void export(
      VaultSession session,
      String selectedDisplayName,
      Path destination,
      VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    Objects.requireNonNull(session, "session");
    Objects.requireNonNull(selectedDisplayName, "selectedDisplayName");
    Objects.requireNonNull(destination, "destination");
    Objects.requireNonNull(control, "control");
    control.checkpoint();
    ManifestEntry entry =
        session.manifest().entries().stream()
            .filter(candidate -> candidate.displayName().equals(selectedDisplayName))
            .findFirst()
            .orElseThrow(() -> new VaultOperationException(JobFailureCategory.INPUT_REJECTED));

    try (var target = ExportFileTarget.create(destination)) {
      target.write(
          output -> {
            try {
              FileRecordReader.streamTo(
                  session.channel(),
                  session.keys(),
                  entry,
                  session.authenticatedCommitEnd(),
                  output,
                  control::isCancellationRequested);
            } catch (VaultDataException exception) {
              throw new ExportAuthenticationFailure();
            }
          });
      // Cancellation is still safe before publication: close removes the unpublished temporary.
      control.checkpoint();
      target.publish();
    } catch (ExportAuthenticationFailure exception) {
      throw new VaultOperationException(JobFailureCategory.SECURITY);
    } catch (SecurityException exception) {
      throw new VaultOperationException(JobFailureCategory.SECURITY);
    } catch (IOException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    }
  }

  /** Keeps authenticated-data failure distinct while satisfying the platform writer contract. */
  private static final class ExportAuthenticationFailure extends IOException {
    private static final long serialVersionUID = 1L;

    private ExportAuthenticationFailure() {
      super((String) null);
      setStackTrace(new StackTraceElement[0]);
    }
  }
}
