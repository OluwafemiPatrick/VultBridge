package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.service.VaultCreator;
import com.vultbridge.service.VaultUnlocker;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies commit-selection invariants, durability ordering, and interruption-safe slot writes. */
class AppendCommitProtocolTest {
  @TempDir Path temporaryDirectory;

  @Test
  void mutationForcesRecordsThenInstallsOnlyTheNextInactiveSlot() throws Exception {
    try (FileChannel channel = newVaultChannel()) {
      var actions = new CountingActions();
      var protocol = AppendCommitProtocol.forMutation(channel, activeSlot(0, 7), actions);
      RecordRef commit = protocol.appendBoundedRecord(id(1), RecordRole.COMMIT, encryptedBody(1));
      UnverifiedHeaderSlot next = slotFor(1, 8, commit);
      assertThrows(IllegalStateException.class, () -> protocol.installInactiveSlot(next));

      protocol.forceAppendedRecords();
      protocol.installInactiveSlot(next);

      assertEquals(2, actions.forceCount);
      assertArrayEquals(
          FixedHeaderCodec.encodeSlot(next),
          read(channel, VaultFormat.HEADER_SLOT_B_OFFSET, VaultFormat.HEADER_SLOT_BYTES));
    }
  }

  @Test
  void rejectsWrongSlotGenerationPointerAndUnsignedExhaustion() throws Exception {
    try (FileChannel channel = newVaultChannel()) {
      var protocol =
          AppendCommitProtocol.forMutation(channel, activeSlot(0, 7), new CountingActions());
      RecordRef commit = protocol.appendBoundedRecord(id(2), RecordRole.COMMIT, encryptedBody(2));
      protocol.forceAppendedRecords();

      assertThrows(
          IllegalArgumentException.class,
          () -> protocol.installInactiveSlot(slotFor(0, 8, commit)));
      assertThrows(
          IllegalArgumentException.class,
          () -> protocol.installInactiveSlot(slotFor(1, 7, commit)));
      assertThrows(
          IllegalArgumentException.class,
          () -> protocol.installInactiveSlot(slotFor(1, 8, differentPointer(commit))));
    }

    try (FileChannel channel = newVaultChannel()) {
      var exhausted =
          AppendCommitProtocol.forMutation(channel, activeSlot(0, -1L), new CountingActions());
      RecordRef commit = exhausted.appendBoundedRecord(id(3), RecordRole.COMMIT, encryptedBody(3));
      exhausted.forceAppendedRecords();
      assertThrows(
          IllegalStateException.class, () -> exhausted.installInactiveSlot(slotFor(1, 0, commit)));
    }
  }

  @Test
  void requiresFinalCommitAndValidAeadBodyBeforeForce() throws Exception {
    try (FileChannel channel = newVaultChannel()) {
      var protocol = AppendCommitProtocol.forCreation(channel, new CountingActions());
      assertThrows(
          IllegalArgumentException.class,
          () -> protocol.appendBoundedRecord(id(4), RecordRole.MANIFEST, new byte[15]));
      protocol.appendBoundedRecord(id(5), RecordRole.MANIFEST, encryptedBody(5));
      assertThrows(IllegalStateException.class, protocol::forceAppendedRecords);
      protocol.appendBoundedRecord(id(6), RecordRole.COMMIT, encryptedBody(6));
      assertThrows(
          IllegalStateException.class,
          () -> protocol.appendBoundedRecord(id(7), RecordRole.MANIFEST, encryptedBody(7)));
    }
  }

  @Test
  void creationRequiresTwoGenerationOneSlotsPointingToFinalCommit() throws Exception {
    try (FileChannel channel = newVaultChannel()) {
      var protocol = AppendCommitProtocol.forCreation(channel, new CountingActions());
      RecordRef commit = protocol.appendBoundedRecord(id(8), RecordRole.COMMIT, encryptedBody(8));
      protocol.forceAppendedRecords();

      assertThrows(
          IllegalStateException.class,
          () -> protocol.installInitialSlots(slotFor(0, 2, commit), slotFor(1, 1, commit)));
      assertThrows(
          IllegalStateException.class,
          () ->
              protocol.installInitialSlots(
                  slotFor(0, 1, commit), slotFor(1, 1, differentPointer(commit))));

      protocol.installInitialSlots(slotFor(0, 1, commit), slotFor(1, 1, commit));
    }
  }

  @Test
  void recordForceFailureLeavesBothExistingSlotsUntouched() throws Exception {
    try (FileChannel channel = newVaultChannel()) {
      byte[] beforeA = read(channel, VaultFormat.HEADER_SLOT_A_OFFSET, 80);
      byte[] beforeB = read(channel, VaultFormat.HEADER_SLOT_B_OFFSET, 80);
      var protocol = AppendCommitProtocol.forCreation(channel, new FailingForceActions());
      protocol.appendBoundedRecord(id(9), RecordRole.COMMIT, encryptedBody(9));

      assertThrows(IOException.class, protocol::forceAppendedRecords);
      assertArrayEquals(beforeA, read(channel, VaultFormat.HEADER_SLOT_A_OFFSET, 80));
      assertArrayEquals(beforeB, read(channel, VaultFormat.HEADER_SLOT_B_OFFSET, 80));
    }
  }

  @Test
  void appendBodyFailureLeavesBothExistingSlotsUntouched() throws Exception {
    try (FileChannel channel = newVaultChannel()) {
      byte[] beforeA = read(channel, VaultFormat.HEADER_SLOT_A_OFFSET, 80);
      byte[] beforeB = read(channel, VaultFormat.HEADER_SLOT_B_OFFSET, 80);
      var protocol = AppendCommitProtocol.forCreation(channel, new FailAtWriteActions(2));

      assertThrows(
          IOException.class,
          () -> protocol.appendBoundedRecord(id(10), RecordRole.COMMIT, encryptedBody(10)));
      assertArrayEquals(beforeA, read(channel, VaultFormat.HEADER_SLOT_A_OFFSET, 80));
      assertArrayEquals(beforeB, read(channel, VaultFormat.HEADER_SLOT_B_OFFSET, 80));
    }
  }

  @Test
  void slotWriteAndPostWriteForceFailuresPreserveTheActiveSlot() throws Exception {
    for (AppendCommitProtocol.DurabilityActions actions :
        java.util.List.of(new FailAtWriteActions(3), new FailAtForceActions(2))) {
      try (FileChannel channel = newVaultChannel()) {
        byte[] beforeA = read(channel, VaultFormat.HEADER_SLOT_A_OFFSET, 80);
        var protocol = AppendCommitProtocol.forMutation(channel, activeSlot(0, 1), actions);
        RecordRef commit =
            protocol.appendBoundedRecord(id(11), RecordRole.COMMIT, encryptedBody(11));
        protocol.forceAppendedRecords();

        assertThrows(IOException.class, () -> protocol.installInactiveSlot(slotFor(1, 2, commit)));
        assertArrayEquals(beforeA, read(channel, VaultFormat.HEADER_SLOT_A_OFFSET, 80));
      }
    }
  }

  @Test
  void everyInterruptedMutationReopensThePreviousRealCommit() throws Exception {
    Path baseline = temporaryDirectory.resolve("baseline.vltb");
    try (var passphrase = passphrase();
        var ignored = VaultCreator.create(baseline, passphrase)) {
      assertEquals(0, ignored.manifest().fileCount());
    }
    byte[] baselineBytes = Files.readAllBytes(baseline);
    AuthenticatedHeaderSlot active =
        new AuthenticatedHeaderSlot(
            FixedHeaderCodec.parse(
                    java.util.Arrays.copyOf(baselineBytes, VaultFormat.FIXED_HEADER_BYTES))
                .slotA());

    for (int interruption = 0; interruption < 4; interruption++) {
      Path scenario = temporaryDirectory.resolve("interrupted-" + interruption + ".vltb");
      Files.write(scenario, baselineBytes);
      AppendCommitProtocol.DurabilityActions actions = interruptionActions(interruption);
      try (FileChannel channel =
          FileChannel.open(scenario, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
        var protocol = AppendCommitProtocol.forMutation(channel, active, actions);
        if (interruption == 0) {
          assertThrows(
              IOException.class,
              () -> protocol.appendBoundedRecord(id(20), RecordRole.COMMIT, encryptedBody(20)));
        } else {
          RecordRef commit =
              protocol.appendBoundedRecord(
                  id(20 + interruption), RecordRole.COMMIT, encryptedBody(20 + interruption));
          if (interruption == 1) {
            assertThrows(IOException.class, protocol::forceAppendedRecords);
          } else {
            protocol.forceAppendedRecords();
            assertThrows(
                IOException.class, () -> protocol.installInactiveSlot(slotFor(1, 2, commit)));
          }
        }
      }

      try (var passphrase = passphrase();
          var reopened = VaultUnlocker.open(scenario, passphrase)) {
        assertEquals(0, reopened.manifest().fileCount());
      }
    }
  }

  @Test
  void refusesBoundedFileAppend() throws Exception {
    try (FileChannel channel = newVaultChannel()) {
      var protocol = AppendCommitProtocol.forCreation(channel);
      assertThrows(
          IllegalArgumentException.class,
          () -> protocol.appendBoundedRecord(id(12), RecordRole.FILE, encryptedBody(12)));
    }
  }

  private FileChannel newVaultChannel() throws IOException {
    FileChannel channel =
        FileChannel.open(
            temporaryDirectory.resolve("vault-" + java.util.UUID.randomUUID() + ".vltb"),
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.READ,
            StandardOpenOption.WRITE);
    channel.write(ByteBuffer.wrap(new byte[VaultFormat.FIXED_HEADER_BYTES]));
    return channel;
  }

  private static AuthenticatedHeaderSlot activeSlot(int index, long generation) {
    return new AuthenticatedHeaderSlot(
        new UnverifiedHeaderSlot(
            index, generation, id(99).bytes(), 400, 80, new byte[VaultFormat.HMAC_SHA256_BYTES]));
  }

  private static UnverifiedHeaderSlot slotFor(int index, long generation, RecordRef commit) {
    return new UnverifiedHeaderSlot(
        index,
        generation,
        commit.recordId().bytes(),
        commit.offset(),
        commit.storedLength(),
        new byte[VaultFormat.HMAC_SHA256_BYTES]);
  }

  private static RecordRef differentPointer(RecordRef commit) {
    return new RecordRef(id(98), commit.offset(), commit.storedLength(), RecordRole.COMMIT);
  }

  private static byte[] encryptedBody(int marker) {
    byte[] body = new byte[VaultFormat.AEAD_TAG_BYTES];
    body[0] = (byte) marker;
    return body;
  }

  private static AppendCommitProtocol.DurabilityActions interruptionActions(int interruption) {
    return switch (interruption) {
      case 0 -> new PartialThenFailWriteActions(2, 8);
      case 1 -> new FailAtForceActions(1);
      case 2 -> new PartialThenFailWriteActions(3, 17);
      case 3 -> new FailAtForceActions(2);
      default -> throw new IllegalArgumentException("Unknown interruption");
    };
  }

  private static com.vultbridge.crypto.SensitiveBytes passphrase() {
    return PassphraseEncoding.encode("correct horse battery staple".toCharArray());
  }

  private static RecordId id(int value) {
    byte[] bytes = new byte[16];
    bytes[15] = (byte) value;
    return new RecordId(bytes);
  }

  private static byte[] read(FileChannel channel, long offset, int length) throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(length);
    while (buffer.hasRemaining()) {
      if (channel.read(buffer, offset + buffer.position()) < 0) {
        throw new IOException("Unexpected EOF in test fixture");
      }
    }
    return buffer.array();
  }

  private static class CountingActions implements AppendCommitProtocol.DurabilityActions {
    private int forceCount;

    @Override
    public void write(FileChannel channel, ByteBuffer source, long offset) throws IOException {
      RecordFrameCodec.writeFully(channel, source, offset);
    }

    @Override
    public void force(FileChannel channel) throws IOException {
      forceCount++;
      channel.force(true);
    }
  }

  private static final class FailingForceActions extends CountingActions {
    @Override
    public void force(FileChannel channel) throws IOException {
      throw new IOException("Synthetic force failure");
    }
  }

  private static final class FailAtWriteActions extends CountingActions {
    private final int failureWrite;
    private int writes;

    private FailAtWriteActions(int failureWrite) {
      this.failureWrite = failureWrite;
    }

    @Override
    public void write(FileChannel channel, ByteBuffer source, long offset) throws IOException {
      writes++;
      if (writes == failureWrite) {
        throw new IOException("Synthetic write failure");
      }
      super.write(channel, source, offset);
    }
  }

  private static final class FailAtForceActions extends CountingActions {
    private final int failureForce;
    private int forces;

    private FailAtForceActions(int failureForce) {
      this.failureForce = failureForce;
    }

    @Override
    public void force(FileChannel channel) throws IOException {
      forces++;
      if (forces == failureForce) {
        throw new IOException("Synthetic force failure");
      }
      super.force(channel);
    }
  }

  private static final class PartialThenFailWriteActions extends CountingActions {
    private final int failureWrite;
    private final int prefixBytes;
    private int writes;

    private PartialThenFailWriteActions(int failureWrite, int prefixBytes) {
      this.failureWrite = failureWrite;
      this.prefixBytes = prefixBytes;
    }

    @Override
    public void write(FileChannel channel, ByteBuffer source, long offset) throws IOException {
      writes++;
      if (writes == failureWrite) {
        ByteBuffer prefix = source.slice();
        prefix.limit(Math.min(prefix.remaining(), prefixBytes));
        RecordFrameCodec.writeFully(channel, prefix, offset);
        throw new IOException("Synthetic partial-write failure");
      }
      super.write(channel, source, offset);
    }
  }
}
