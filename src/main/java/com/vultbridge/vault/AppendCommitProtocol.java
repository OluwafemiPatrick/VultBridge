package com.vultbridge.vault;

import com.vultbridge.crypto.VaultKeySet;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Enforces the append, force, inactive-slot-write, force durability sequence for vault updates.
 *
 * <p>The protocol appends only bounded MANIFEST and COMMIT bodies in Phase 3; FILE streaming is
 * introduced by Phase 4. It never scans or promotes tail data. A package-private I/O seam permits
 * deterministic interruption at each durability boundary while production delegates to positional
 * channel writes and {@link FileChannel#force(boolean)}.
 */
public final class AppendCommitProtocol {
  private final FileChannel channel;
  private final DurabilityActions actions;
  private final AuthenticatedHeaderSlot activeSlot;
  private State state = State.CLEAN;
  private RecordRef finalAppendedRecord;

  private AppendCommitProtocol(
      FileChannel channel, AuthenticatedHeaderSlot activeSlot, DurabilityActions actions) {
    this.channel = Objects.requireNonNull(channel, "channel");
    this.activeSlot = activeSlot;
    this.actions = Objects.requireNonNull(actions, "actions");
  }

  /** Creates a production protocol for the first records and slots of a new vault. */
  public static AppendCommitProtocol forCreation(FileChannel channel) {
    return new AppendCommitProtocol(channel, null, DurabilityActions.PRODUCTION);
  }

  /** Creates a production mutation protocol anchored to the authenticated active slot. */
  public static AppendCommitProtocol forMutation(
      FileChannel channel, AuthenticatedHeaderSlot activeSlot) {
    return new AppendCommitProtocol(
        channel, Objects.requireNonNull(activeSlot, "activeSlot"), DurabilityActions.PRODUCTION);
  }

  static AppendCommitProtocol forCreation(FileChannel channel, DurabilityActions actions) {
    return new AppendCommitProtocol(channel, null, actions);
  }

  /**
   * Creates a mutation protocol with injected writes and forces for durability verification.
   *
   * <p>This seam is public only inside the non-exported vault module package boundary; application
   * production code uses {@link #forMutation(FileChannel, AuthenticatedHeaderSlot)}.
   */
  public static AppendCommitProtocol forMutation(
      FileChannel channel, AuthenticatedHeaderSlot activeSlot, DurabilityActions actions) {
    return new AppendCommitProtocol(
        channel, Objects.requireNonNull(activeSlot, "activeSlot"), actions);
  }

  /** Appends one bounded encrypted MANIFEST or COMMIT frame and returns its exact reference. */
  public RecordRef appendBoundedRecord(RecordId recordId, RecordRole role, byte[] encryptedBody)
      throws IOException {
    Objects.requireNonNull(recordId, "recordId");
    Objects.requireNonNull(role, "role");
    Objects.requireNonNull(encryptedBody, "encryptedBody");
    if (role == RecordRole.FILE) {
      throw new IllegalArgumentException("FILE records require the streaming append path");
    }
    if (finalAppendedRecord != null) {
      throw new IllegalStateException("No records may follow the final COMMIT");
    }
    int maximumPlaintext =
        role == RecordRole.MANIFEST
            ? VaultFormat.MAXIMUM_MANIFEST_PLAINTEXT_BYTES
            : VaultFormat.MAXIMUM_COMMIT_PLAINTEXT_BYTES;
    if (encryptedBody.length < VaultFormat.AEAD_TAG_BYTES
        || encryptedBody.length > maximumPlaintext + VaultFormat.AEAD_TAG_BYTES) {
      throw new IllegalArgumentException("Encrypted record body exceeds its role bound");
    }
    long offset = channel.size();
    if (offset < VaultFormat.FIXED_HEADER_BYTES) {
      throw new IOException("Vault header is incomplete");
    }
    var header = new RecordFrameHeader(recordId, encryptedBody.length);
    actions.write(channel, ByteBuffer.wrap(RecordFrameCodec.encodeHeader(header)), offset);
    actions.write(
        channel,
        ByteBuffer.wrap(encryptedBody),
        Math.addExact(offset, VaultFormat.RECORD_FRAME_HEADER_BYTES));
    state = State.APPENDED;
    var reference = new RecordRef(recordId, offset, encryptedBody.length, role);
    if (role == RecordRole.COMMIT) {
      finalAppendedRecord = reference;
    }
    return reference;
  }

  /**
   * Streams one complete FILE record from a fixed-size source into encrypted vault chunks.
   *
   * <p>The source is borrowed and never closed. One reusable 4 MiB plaintext buffer is wiped after
   * each chunk and again on exit. Cancellation is observed only between complete authenticated
   * chunks; a cancelled or failed record remains unreachable because no COMMIT has been installed.
   */
  public RecordRef appendFileRecord(
      RecordId recordId,
      FileRecordLayout layout,
      VaultKeySet keys,
      FileChannel source,
      BooleanSupplier cancellationRequested)
      throws IOException {
    Objects.requireNonNull(recordId, "recordId");
    Objects.requireNonNull(layout, "layout");
    Objects.requireNonNull(keys, "keys");
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(cancellationRequested, "cancellationRequested");
    if (finalAppendedRecord != null) {
      throw new IllegalStateException("No records may follow the final COMMIT");
    }
    long offset = channel.size();
    if (offset < VaultFormat.FIXED_HEADER_BYTES) {
      throw new IOException("Vault header is incomplete");
    }
    actions.write(
        channel,
        ByteBuffer.wrap(
            RecordFrameCodec.encodeHeader(new RecordFrameHeader(recordId, layout.storedLength()))),
        offset);

    byte[] plaintext = new byte[VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES];
    long sourceOffset = 0;
    long bodyOffset = Math.addExact(offset, VaultFormat.RECORD_FRAME_HEADER_BYTES);
    try {
      for (long chunkIndex = 0; chunkIndex < layout.chunkCount(); chunkIndex++) {
        if (cancellationRequested.getAsBoolean()) {
          throw new CancellationException();
        }
        int plaintextLength = layout.chunkPlaintextLength(chunkIndex);
        readSourceFully(source, plaintext, plaintextLength, sourceOffset);
        byte[] encrypted =
            RecordCrypto.encryptFileChunkPrefix(
                keys, recordId, layout, chunkIndex, plaintext, plaintextLength);
        // Clear the reusable plaintext before the ciphertext write can block or fail.
        Arrays.fill(plaintext, (byte) 0);
        actions.write(channel, ByteBuffer.wrap(encrypted), bodyOffset);
        sourceOffset = Math.addExact(sourceOffset, plaintextLength);
        bodyOffset = Math.addExact(bodyOffset, encrypted.length);
      }
    } finally {
      Arrays.fill(plaintext, (byte) 0);
    }
    long expectedEnd =
        Math.addExact(
            offset, Math.addExact(VaultFormat.RECORD_FRAME_HEADER_BYTES, layout.storedLength()));
    if (bodyOffset != expectedEnd) {
      throw new IllegalStateException("FILE record length diverged from its canonical layout");
    }
    state = State.APPENDED;
    return new RecordRef(recordId, offset, layout.storedLength(), RecordRole.FILE);
  }

  /** Forces all appended record bytes and metadata before any pointer slot may change. */
  public void forceAppendedRecords() throws IOException {
    if (state != State.APPENDED || finalAppendedRecord == null) {
      throw new IllegalStateException("A final COMMIT must be appended before forcing records");
    }
    actions.force(channel);
    state = State.RECORDS_FORCED;
  }

  /** Writes the inactive authenticated slot and forces it as the final commit point. */
  public void installInactiveSlot(UnverifiedHeaderSlot slot) throws IOException {
    Objects.requireNonNull(slot, "slot");
    if (activeSlot == null || state != State.RECORDS_FORCED) {
      throw new IllegalStateException("A mutation requires forced records and an active slot");
    }
    if (activeSlot.generation() == -1L) {
      throw new IllegalStateException("Header-slot generation is exhausted");
    }
    long expectedGeneration = activeSlot.generation() + 1;
    int expectedIndex = 1 - activeSlot.slotIndex();
    if (slot.slotIndex() != expectedIndex
        || slot.generation() != expectedGeneration
        || !slotPointsTo(slot, finalAppendedRecord)) {
      throw new IllegalArgumentException(
          "Slot must be the next inactive pointer to the final COMMIT");
    }
    long offset =
        slot.slotIndex() == 0 ? VaultFormat.HEADER_SLOT_A_OFFSET : VaultFormat.HEADER_SLOT_B_OFFSET;
    actions.write(channel, ByteBuffer.wrap(FixedHeaderCodec.encodeSlot(slot)), offset);
    state = State.SLOT_WRITTEN;
    actions.force(channel);
    state = State.CLEAN;
  }

  /**
   * Returns whether a complete mutation slot write occurred but its force operation failed.
   *
   * <p>The resulting on-disk selection is uncertain: the new authenticated slot may be visible now
   * but is not known durable. Callers must close and reopen the session instead of continuing from
   * stale in-memory metadata.
   */
  public boolean hasUnforcedSlotWrite() {
    return state == State.SLOT_WRITTEN;
  }

  /** Installs and forces both initial authenticated slots while creating a brand-new vault. */
  public void installInitialSlots(UnverifiedHeaderSlot slotA, UnverifiedHeaderSlot slotB)
      throws IOException {
    Objects.requireNonNull(slotA, "slotA");
    Objects.requireNonNull(slotB, "slotB");
    if (activeSlot != null
        || state != State.RECORDS_FORCED
        || slotA.slotIndex() != 0
        || slotB.slotIndex() != 1
        || slotA.generation() != 1
        || slotB.generation() != 1
        || !slotPointsTo(slotA, finalAppendedRecord)
        || !slotPointsTo(slotB, finalAppendedRecord)) {
      throw new IllegalStateException("Initial slots require forced records and physical order");
    }
    actions.write(
        channel,
        ByteBuffer.wrap(FixedHeaderCodec.encodeSlot(slotA)),
        VaultFormat.HEADER_SLOT_A_OFFSET);
    actions.write(
        channel,
        ByteBuffer.wrap(FixedHeaderCodec.encodeSlot(slotB)),
        VaultFormat.HEADER_SLOT_B_OFFSET);
    actions.force(channel);
    state = State.CLEAN;
  }

  private static boolean slotPointsTo(UnverifiedHeaderSlot slot, RecordRef commitRef) {
    return commitRef != null
        && commitRef.expectedRole() == RecordRole.COMMIT
        && java.util.Arrays.equals(slot.commitRecordId(), commitRef.recordId().bytes())
        && slot.commitOffset() == commitRef.offset()
        && slot.commitStoredLength() == commitRef.storedLength();
  }

  private static void readSourceFully(
      FileChannel source, byte[] destination, int length, long sourceOffset) throws IOException {
    ByteBuffer buffer = ByteBuffer.wrap(destination, 0, length);
    long position = sourceOffset;
    while (buffer.hasRemaining()) {
      int read = source.read(buffer, position);
      if (read <= 0) {
        throw new IOException("Import source ended before its inspected size");
      }
      position = Math.addExact(position, read);
    }
  }

  /** Supplies positional writes and force operations for deterministic durability fault tests. */
  public interface DurabilityActions {
    DurabilityActions PRODUCTION =
        new DurabilityActions() {
          @Override
          public void write(FileChannel channel, ByteBuffer source, long offset)
              throws IOException {
            RecordFrameCodec.writeFully(channel, source, offset);
          }

          @Override
          public void force(FileChannel channel) throws IOException {
            channel.force(true);
          }
        };

    /** Writes the complete source at the requested absolute vault offset. */
    void write(FileChannel channel, ByteBuffer source, long offset) throws IOException;

    /** Requests durable persistence of preceding vault data and metadata writes. */
    void force(FileChannel channel) throws IOException;
  }

  private enum State {
    CLEAN,
    APPENDED,
    RECORDS_FORCED,
    SLOT_WRITTEN
  }
}
