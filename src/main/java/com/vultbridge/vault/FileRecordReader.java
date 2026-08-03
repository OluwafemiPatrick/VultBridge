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
 * Streams one authenticated v1 FILE record into a caller-owned destination channel.
 *
 * <p>The reader validates the authenticated reference against the commit end and exact public frame
 * before allocating a computed chunk buffer. Each chunk is fully authenticated before any of its
 * plaintext is written. Plaintext is bounded to one chunk and wiped after use; neither source nor
 * destination channels are closed.
 */
public final class FileRecordReader {
  private FileRecordReader() {}

  /**
   * Authenticates and writes every chunk of one manifest entry.
   *
   * @return the exact logical plaintext byte count written
   * @throws VaultDataException for a malformed frame, range, length, or authentication failure
   * @throws CancellationException when cancellation is observed between complete chunks
   */
  public static long streamTo(
      FileChannel vault,
      VaultKeySet keys,
      ManifestEntry entry,
      long authenticatedCommitEnd,
      FileChannel destination,
      BooleanSupplier cancellationRequested)
      throws IOException, VaultDataException {
    Objects.requireNonNull(vault, "vault");
    Objects.requireNonNull(keys, "keys");
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(destination, "destination");
    Objects.requireNonNull(cancellationRequested, "cancellationRequested");

    FileRecordLayout layout = FileRecordLayout.forLogicalSize(entry.logicalSize());
    final long[] outputOffset = {0};
    streamChunks(
        vault,
        keys,
        entry,
        authenticatedCommitEnd,
        cancellationRequested,
        (chunkIndex, plaintext, plaintextLength) -> {
          writeFully(destination, ByteBuffer.wrap(plaintext, 0, plaintextLength), outputOffset[0]);
          outputOffset[0] = Math.addExact(outputOffset[0], plaintextLength);
        });
    if (outputOffset[0] != layout.logicalSize()) {
      throw new VaultDataException();
    }
    return outputOffset[0];
  }

  /** Authenticates every chunk of one FILE record without retaining or publishing plaintext. */
  public static long verify(
      FileChannel vault,
      VaultKeySet keys,
      ManifestEntry entry,
      long authenticatedCommitEnd,
      BooleanSupplier cancellationRequested)
      throws IOException, VaultDataException {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(entry.logicalSize());
    final long[] verifiedBytes = {0};
    streamChunks(
        vault,
        keys,
        entry,
        authenticatedCommitEnd,
        cancellationRequested,
        (chunkIndex, plaintext, plaintextLength) -> {
          verifiedBytes[0] = Math.addExact(verifiedBytes[0], plaintextLength);
        });
    if (verifiedBytes[0] != layout.logicalSize()) {
      throw new VaultDataException();
    }
    return verifiedBytes[0];
  }

  /**
   * Authenticates each FILE chunk and passes one wiped borrowed plaintext buffer to a package-local
   * consumer. This is the bounded-memory bridge used when compacting one authenticated vault into
   * another; the consumer must finish synchronously and must not retain the buffer.
   */
  static void streamChunks(
      FileChannel vault,
      VaultKeySet keys,
      ManifestEntry entry,
      long authenticatedCommitEnd,
      BooleanSupplier cancellationRequested,
      PlaintextChunkConsumer consumer)
      throws IOException, VaultDataException {
    Objects.requireNonNull(vault, "vault");
    Objects.requireNonNull(keys, "keys");
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(cancellationRequested, "cancellationRequested");
    Objects.requireNonNull(consumer, "consumer");

    RecordRef reference = entry.fileRef();
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(entry.logicalSize());
    if (reference.expectedRole() != RecordRole.FILE
        || reference.storedLength() != layout.storedLength()
        || entry.chunkCount() != layout.chunkCount()) {
      throw new VaultDataException();
    }
    RecordFrameCodec.readVerifiedHeader(vault, reference, authenticatedCommitEnd);

    for (long chunkIndex = 0; chunkIndex < layout.chunkCount(); chunkIndex++) {
      if (cancellationRequested.getAsBoolean()) {
        throw new CancellationException();
      }
      int plaintextLength = layout.chunkPlaintextLength(chunkIndex);
      int encryptedLength = Math.addExact(plaintextLength, VaultFormat.AEAD_TAG_BYTES);
      long encryptedOffset =
          Math.addExact(
              Math.addExact(reference.offset(), VaultFormat.RECORD_FRAME_HEADER_BYTES),
              layout.chunkStoredOffset(chunkIndex));
      byte[] encrypted = readExact(vault, encryptedOffset, encryptedLength);
      try (var plaintext =
          RecordCrypto.decryptFileChunk(
              keys, reference.recordId(), layout, chunkIndex, encrypted)) {
        byte[] copy = plaintext.copy();
        try {
          consumer.accept(chunkIndex, copy, plaintextLength);
        } finally {
          Arrays.fill(copy, (byte) 0);
        }
      }
    }
  }

  private static byte[] readExact(FileChannel channel, long offset, int length)
      throws IOException, VaultDataException {
    byte[] bytes = new byte[length];
    ByteBuffer destination = ByteBuffer.wrap(bytes);
    long position = offset;
    while (destination.hasRemaining()) {
      int read = channel.read(destination, position);
      if (read <= 0) {
        throw new VaultDataException();
      }
      position = Math.addExact(position, read);
    }
    return bytes;
  }

  @FunctionalInterface
  interface PlaintextChunkConsumer {
    void accept(long chunkIndex, byte[] plaintext, int plaintextLength) throws IOException;
  }

  private static void writeFully(FileChannel channel, ByteBuffer source, long offset)
      throws IOException {
    long position = offset;
    while (source.hasRemaining()) {
      int written = channel.write(source, position);
      if (written <= 0) {
        throw new IOException("Unable to complete authenticated output write");
      }
      position = Math.addExact(position, written);
    }
  }
}
