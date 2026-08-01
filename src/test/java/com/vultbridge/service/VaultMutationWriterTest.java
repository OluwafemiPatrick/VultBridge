package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.vault.AppendCommitProtocol;
import com.vultbridge.vault.VaultManifest;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies durable mutation installation and session-state advancement. */
class VaultMutationWriterTest {
  @TempDir Path temporaryDirectory;

  @Test
  void successiveMutationsAlternateSlotsAndPersistAfterReopen() throws Exception {
    Path vault = temporaryDirectory.resolve("mutations.vltb");
    int firstIndex;
    long firstGeneration;
    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      var control = new NeverCancelledControl();
      firstIndex = session.activeSlot().slotIndex();
      firstGeneration = session.activeSlot().generation();

      VaultSnapshot first =
          VaultMutationWriter.commit(
              session,
              AppendCommitProtocol.forMutation(session.channel(), session.activeSlot()),
              new VaultManifest(List.of()),
              control);
      assertSame(first.manifest(), session.manifest());
      assertEquals(1 - firstIndex, session.activeSlot().slotIndex());
      assertEquals(firstGeneration + 1, session.activeSlot().generation());

      VaultMutationWriter.commit(
          session,
          AppendCommitProtocol.forMutation(session.channel(), session.activeSlot()),
          new VaultManifest(List.of()),
          control);
      assertEquals(firstIndex, session.activeSlot().slotIndex());
      assertEquals(firstGeneration + 2, session.activeSlot().generation());
    }

    try (var passphrase = passphrase();
        var reopened = VaultUnlocker.open(vault, passphrase)) {
      assertEquals(0, reopened.manifest().fileCount());
      assertEquals(firstGeneration + 2, reopened.activeSlot().generation());
    }
  }

  @Test
  void cancellationBeforeMutationRetainsSessionAndDiskState() throws Exception {
    Path vault = temporaryDirectory.resolve("cancel-mutation.vltb");
    try (var passphrase = passphrase();
        var session = VaultCreator.create(vault, passphrase)) {
      var originalManifest = session.manifest();
      var originalSlot = session.activeSlot();
      assertThrows(
          JobCancelledException.class,
          () ->
              VaultMutationWriter.commit(
                  session,
                  AppendCommitProtocol.forMutation(session.channel(), session.activeSlot()),
                  new VaultManifest(List.of()),
                  new CancelledControl()));
      assertSame(originalManifest, session.manifest());
      assertSame(originalSlot, session.activeSlot());
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

  private static final class CancelledControl implements VaultOperationControl {
    @Override
    public boolean isCancellationRequested() {
      return true;
    }

    @Override
    public void checkpoint() throws JobCancelledException {
      throw new JobCancelledException();
    }

    @Override
    public void reportProgress(JobProgress progress) throws JobCancelledException {
      throw new JobCancelledException();
    }
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return PassphraseEncoding.encode("correct horse battery staple".toCharArray());
  }
}
