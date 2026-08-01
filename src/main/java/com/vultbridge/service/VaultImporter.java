package com.vultbridge.service;

import com.vultbridge.platform.SourceFileInspector;
import com.vultbridge.platform.SourceFileRejectedException;
import com.vultbridge.platform.SourceFileSnapshot;
import com.vultbridge.vault.AppendCommitProtocol;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.VaultManifest;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Imports regular files sequentially into one authenticated unlocked vault session.
 *
 * <p>Each source is independently preflighted, opened without following links, streamed into an
 * encrypted FILE record, and inspected again before its manifest entry is committed. A failed or
 * changed source can leave unreachable ciphertext in the append tail but cannot create an incorrect
 * committed entry. Host paths are borrowed only for the active call and are never retained, logged,
 * or returned.
 */
public final class VaultImporter {
  private VaultImporter() {}

  /**
   * Imports each selected source in order and returns the final authenticated metadata snapshot.
   */
  public static VaultSnapshot importFiles(
      VaultSession session, List<Path> sources, VaultOperationControl control)
      throws VaultOperationException, JobCancelledException {
    return importFiles(session, sources, control, Clock.systemUTC(), SourceFileInspector::inspect);
  }

  static VaultSnapshot importFiles(
      VaultSession session,
      List<Path> sources,
      VaultOperationControl control,
      Clock clock,
      SourceProbe sourceProbe)
      throws VaultOperationException, JobCancelledException {
    Objects.requireNonNull(session, "session");
    Objects.requireNonNull(sources, "sources");
    Objects.requireNonNull(control, "control");
    Objects.requireNonNull(clock, "clock");
    Objects.requireNonNull(sourceProbe, "sourceProbe");
    List<Path> selectedSources = List.copyOf(sources);
    if (selectedSources.isEmpty()) {
      throw new VaultOperationException(JobFailureCategory.INPUT_REJECTED);
    }

    control.reportProgress(new JobProgress(JobPhase.PREPARING, 0, selectedSources.size()));
    VaultSnapshot latest =
        importOne(session, selectedSources.getFirst(), control, clock, sourceProbe);
    for (int index = 1; index < selectedSources.size(); index++) {
      control.reportProgress(new JobProgress(JobPhase.PREPARING, index, selectedSources.size()));
      latest = importOne(session, selectedSources.get(index), control, clock, sourceProbe);
    }
    return latest;
  }

  private static VaultSnapshot importOne(
      VaultSession session,
      Path source,
      VaultOperationControl control,
      Clock clock,
      SourceProbe sourceProbe)
      throws VaultOperationException, JobCancelledException {
    Objects.requireNonNull(source, "source");
    Path fileName = source.getFileName();
    if (fileName == null) {
      throw rejected();
    }

    try {
      SourceFileSnapshot before = sourceProbe.inspect(source);
      ImportPreflight.ValidatedImport validated =
          ImportPreflight.validate(session.manifest(), fileName.toString(), before);
      var protocol = AppendCommitProtocol.forMutation(session.channel(), session.activeSlot());
      var fileId = session.recordIds().next();
      com.vultbridge.vault.RecordRef fileRef;
      try (FileChannel sourceChannel =
          FileChannel.open(source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
        fileRef =
            protocol.appendFileRecord(
                fileId,
                validated.layout(),
                session.keys(),
                sourceChannel,
                control::isCancellationRequested);
      }

      SourceFileSnapshot after = sourceProbe.inspect(source);
      if (!before.matches(after)) {
        throw rejected();
      }
      Instant importedAt = clock.instant();
      var entry =
          new ManifestEntry(
              validated.displayName(),
              fileRef,
              validated.layout().logicalSize(),
              validated.layout().chunkCount(),
              importedAt);
      var entries = new ArrayList<>(session.manifest().entries());
      entries.add(entry);
      return VaultMutationWriter.commit(session, protocol, new VaultManifest(entries), control);
    } catch (VaultOperationException | JobCancelledException exception) {
      throw exception;
    } catch (SourceFileRejectedException | IllegalArgumentException exception) {
      throw rejected();
    } catch (SecurityException exception) {
      throw new VaultOperationException(JobFailureCategory.SECURITY);
    } catch (IOException exception) {
      throw new VaultOperationException(JobFailureCategory.FILESYSTEM);
    }
  }

  private static VaultOperationException rejected() {
    return new VaultOperationException(JobFailureCategory.INPUT_REJECTED);
  }

  /** Test seam for deterministic before/after source-attribute observations. */
  @FunctionalInterface
  interface SourceProbe {
    SourceFileSnapshot inspect(Path path) throws IOException, SourceFileRejectedException;
  }
}
