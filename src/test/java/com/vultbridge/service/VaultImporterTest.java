package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.platform.SourceFileSnapshot;
import com.vultbridge.vault.FileRecordReader;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies transactional sequential imports and post-stream source mutation rejection. */
class VaultImporterTest {
  private static final Clock FIXED_CLOCK =
      Clock.fixed(Instant.parse("2026-08-01T10:45:30Z"), ZoneOffset.UTC);
  @TempDir Path temporaryDirectory;

  @Test
  void importsPersistsAndAuthenticallyReadsOriginalBytes() throws Exception {
    Path vault = temporaryDirectory.resolve("import.vltb");
    Path source = temporaryDirectory.resolve("document.bin");
    byte[] original = {1, 2, 3, 4, 5};
    Files.write(source, original);

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultSnapshot result =
          VaultImporter.importFiles(
              session, List.of(source), new NeverCancelledControl(), FIXED_CLOCK, realProbe());
      assertEquals(1, result.manifest().fileCount());
      assertEquals(FIXED_CLOCK.instant(), result.manifest().entries().getFirst().importedAtUtc());
    }

    Path output = temporaryDirectory.resolve("authenticated.bin");
    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase);
        var destination =
            FileChannel.open(
                output,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE)) {
      var entry = reopened.manifest().entries().getFirst();
      FileRecordReader.streamTo(
          reopened.channel(),
          reopened.keys(),
          entry,
          reopened.authenticatedCommitEnd(),
          destination,
          () -> false);
    }
    assertArrayEquals(original, Files.readAllBytes(output));
  }

  @Test
  void changedSourceLeavesNoCommittedEntry() throws Exception {
    Path vault = temporaryDirectory.resolve("changed.vltb");
    Path source = temporaryDirectory.resolve("changing.bin");
    Files.write(source, new byte[] {1, 2, 3});
    var before = new SourceFileSnapshot(3, Instant.ofEpochMilli(1), "same-key");
    var after = new SourceFileSnapshot(3, Instant.ofEpochMilli(2), "same-key");
    var calls = new java.util.concurrent.atomic.AtomicInteger();

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultOperationException failure =
          assertThrows(
              VaultOperationException.class,
              () ->
                  VaultImporter.importFiles(
                      session,
                      List.of(source),
                      new NeverCancelledControl(),
                      FIXED_CLOCK,
                      ignored -> calls.getAndIncrement() == 0 ? before : after));
      assertEquals(JobFailureCategory.INPUT_REJECTED, failure.category());
      assertEquals(0, session.manifest().fileCount());
    }

    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(0, reopened.manifest().fileCount());
    }
  }

  @Test
  void sequentialImportKeepsEarlierCommitWhenLaterNameDuplicates() throws Exception {
    Path vault = temporaryDirectory.resolve("sequence.vltb");
    Path first = temporaryDirectory.resolve("same.bin");
    Files.write(first, new byte[] {1});

    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      VaultImporter.importFiles(
          session, List.of(first), new NeverCancelledControl(), FIXED_CLOCK, realProbe());
      VaultOperationException failure =
          assertThrows(
              VaultOperationException.class,
              () ->
                  VaultImporter.importFiles(
                      session,
                      List.of(first),
                      new NeverCancelledControl(),
                      FIXED_CLOCK,
                      realProbe()));
      assertEquals(JobFailureCategory.INPUT_REJECTED, failure.category());
      assertEquals(1, session.manifest().fileCount());
    }
  }

  private static VaultImporter.SourceProbe realProbe() {
    return com.vultbridge.platform.SourceFileInspector::inspect;
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
