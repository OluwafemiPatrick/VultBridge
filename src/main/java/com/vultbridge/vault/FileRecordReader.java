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

    RecordRef reference = entry.fileRef();
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(entry.logicalSize());
    if (reference.expectedRole() != RecordRole.FILE
        || reference.storedLength() != layout.storedLength()
        || entry.chunkCount() != layout.chunkCount()) {
      throw new VaultDataException();
    }
    RecordFrameCodec.readVerifiedHeader(vault, reference, authenticatedCommitEnd);

    long outputOffset = 0;
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
          writeFully(destination, ByteBuffer.wrap(copy), outputOffset);
        } finally {
          Arrays.fill(copy, (byte) 0);
        }
      }
      outputOffset = Math.addExact(outputOffset, plaintextLength);
    }
    if (outputOffset != layout.logicalSize()) {
      throw new VaultDataException();
    }
    return outputOffset;
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
