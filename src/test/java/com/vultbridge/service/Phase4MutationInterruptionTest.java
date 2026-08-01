package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.vault.AppendCommitProtocol;
import com.vultbridge.vault.FileRecordLayout;
import com.vultbridge.vault.ManifestEntry;
import com.vultbridge.vault.VaultFormat;
import com.vultbridge.vault.VaultManifest;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies real populated-vault import and delete failure atomicity at every durability boundary.
 */
class Phase4MutationInterruptionTest {
  @TempDir Path temporaryDirectory;

  @Test
  void interruptedFileManifestCommitAndSlotWritesReopenThePreviousManifest() throws Exception {
    byte[] baseline = createPopulatedBaseline();
    Path source = temporaryDirectory.resolve("candidate.bin");
    Files.write(source, new byte[] {4, 5, 6, 7});

    for (int failedWrite = 1; failedWrite <= 7; failedWrite++) {
      assertInterruptedImportReopensBaseline(
          baseline, source, Failure.write(failedWrite), "write-" + failedWrite);
    }
    assertInterruptedImportReopensBaseline(baseline, source, Failure.force(1), "record-force");
    assertInterruptedImportReopensBaseline(baseline, source, Failure.force(2), "slot-force");
  }

  @Test
  void interruptedDeleteManifestCommitAndSlotWritesReopenThePreviousManifest() throws Exception {
    byte[] baseline = createPopulatedBaseline();

    for (int failedWrite = 1; failedWrite <= 5; failedWrite++) {
      assertInterruptedDeleteReopensBaseline(
          baseline, Failure.write(failedWrite), "delete-write-" + failedWrite);
    }
    assertInterruptedDeleteReopensBaseline(baseline, Failure.force(1), "delete-record-force");
    assertInterruptedDeleteReopensBaseline(baseline, Failure.force(2), "delete-slot-force");
  }

  private byte[] createPopulatedBaseline() throws Exception {
    Path baseline = temporaryDirectory.resolve("populated-baseline.vltb");
    Path original = temporaryDirectory.resolve("original.bin");
    Files.write(original, new byte[] {1, 2, 3});
    try (var passphrase = passphrase();
        var session = VaultCreator.create(baseline, passphrase)) {
      VaultImporter.importFiles(session, List.of(original), new NeverCancelledControl());
    }
    return Files.readAllBytes(baseline);
  }

  private void assertInterruptedImportReopensBaseline(
      byte[] baseline, Path source, Failure failure, String scenario) throws Exception {
    Path vault = temporaryDirectory.resolve("interrupted-import-" + scenario + ".vltb");
    Files.write(vault, baseline, StandardOpenOption.CREATE_NEW);
    try (var passphrase = passphrase();
        var session = VaultUnlocker.open(vault, passphrase)) {
      var actions = new FailingDurabilityActions(failure);
      var protocol =
          AppendCommitProtocol.forMutation(session.channel(), session.activeSlot(), actions);

      assertExpectedFailure(failure, () -> appendAndCommitCandidate(session, protocol, source));
      assertEquals(1, session.manifest().fileCount());
      if (failure.forceNumber() == 2) {
        invalidateUnforcedInactiveSlot(session);
      }
    }
    assertBaselineReopens(vault);
  }

  private void assertInterruptedDeleteReopensBaseline(
      byte[] baseline, Failure failure, String scenario) throws Exception {
    Path vault = temporaryDirectory.resolve("interrupted-" + scenario + ".vltb");
    Files.write(vault, baseline, StandardOpenOption.CREATE_NEW);
    try (var passphrase = passphrase();
        var session = VaultUnlocker.open(vault, passphrase)) {
      var actions = new FailingDurabilityActions(failure);
      var protocol =
          AppendCommitProtocol.forMutation(session.channel(), session.activeSlot(), actions);

      assertExpectedFailure(
          failure,
          () ->
              VaultMutationWriter.commit(
                  session, protocol, new VaultManifest(List.of()), new NeverCancelledControl()));
      assertEquals(1, session.manifest().fileCount());
      if (failure.forceNumber() == 2) {
        invalidateUnforcedInactiveSlot(session);
      }
    }
    assertBaselineReopens(vault);
  }

  private static void appendAndCommitCandidate(
      VaultSession session, AppendCommitProtocol protocol, Path source) throws Exception {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(Files.size(source));
    var recordId = session.recordIds().next();
    com.vultbridge.vault.RecordRef fileReference;
    try (var sourceChannel = FileChannel.open(source, StandardOpenOption.READ)) {
      fileReference =
          protocol.appendFileRecord(recordId, layout, session.keys(), sourceChannel, () -> false);
    }
    var nextEntries = new ArrayList<>(session.manifest().entries());
    nextEntries.add(
        new ManifestEntry(
            "candidate.bin",
            fileReference,
            layout.logicalSize(),
            layout.chunkCount(),
            Instant.EPOCH));
    VaultMutationWriter.commit(
        session, protocol, new VaultManifest(nextEntries), new NeverCancelledControl());
  }

  private static void invalidateUnforcedInactiveSlot(VaultSession session) throws IOException {
    int inactiveIndex = 1 - session.activeSlot().slotIndex();
    long slotOffset =
        inactiveIndex == 0 ? VaultFormat.HEADER_SLOT_A_OFFSET : VaultFormat.HEADER_SLOT_B_OFFSET;
    // A force failure means the completed slot write is not guaranteed durable. Invalidating its
    // authentication tag models loss/corruption of that unforced update and proves normal unlock
    // falls back to the untouched preceding authenticated slot.
    long tagByteOffset = slotOffset + VaultFormat.HEADER_SLOT_BYTES - 1;
    ByteBuffer tagByte = ByteBuffer.allocate(1);
    if (session.channel().read(tagByte, tagByteOffset) != 1) {
      throw new IOException("Unable to read injected slot tag");
    }
    tagByte.array()[0] ^= 1;
    writeFully(session.channel(), ByteBuffer.wrap(tagByte.array()), tagByteOffset);
    session.channel().force(true);
  }

  private static void assertBaselineReopens(Path vault) throws Exception {
    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(1, reopened.manifest().fileCount());
      assertEquals("original.bin", reopened.manifest().entries().getFirst().displayName());
    }
  }

  private static void assertExpectedFailure(Failure failure, ThrowingMutation mutation) {
    if (failure.forceNumber() == 2) {
      VaultOperationException uncertain =
          assertThrows(VaultOperationException.class, mutation::run);
      assertTrue(uncertain.sessionInvalidated());
      assertEquals(JobFailureCategory.FILESYSTEM, uncertain.category());
    } else {
      assertThrows(IOException.class, mutation::run);
    }
  }

  private record Failure(int writeNumber, int forceNumber) {
    private static Failure write(int number) {
      return new Failure(number, 0);
    }

    private static Failure force(int number) {
      return new Failure(0, number);
    }
  }

  private static final class FailingDurabilityActions
      implements AppendCommitProtocol.DurabilityActions {
    private final Failure failure;
    private int writes;
    private int forces;

    private FailingDurabilityActions(Failure failure) {
      this.failure = failure;
    }

    @Override
    public void write(FileChannel channel, ByteBuffer source, long offset) throws IOException {
      writes++;
      if (writes == failure.writeNumber()) {
        ByteBuffer partial = source.slice();
        partial.limit(Math.max(1, partial.remaining() / 2));
        writeFully(channel, partial, offset);
        throw new IOException("injected partial write");
      }
      writeFully(channel, source, offset);
    }

    @Override
    public void force(FileChannel channel) throws IOException {
      forces++;
      if (forces == failure.forceNumber()) {
        throw new IOException("injected force failure");
      }
      channel.force(true);
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

  @FunctionalInterface
  private interface ThrowingMutation {
    void run() throws Exception;
  }

  private static void writeFully(FileChannel channel, ByteBuffer source, long offset)
      throws IOException {
    long position = offset;
    while (source.hasRemaining()) {
      int written = channel.write(source, position);
      if (written <= 0) {
        throw new IOException("Unable to complete injected positional write");
      }
      position = Math.addExact(position, written);
    }
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return PassphraseEncoding.encode("correct horse battery staple".toCharArray());
  }
}
