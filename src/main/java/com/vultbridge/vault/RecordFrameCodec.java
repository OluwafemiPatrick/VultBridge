package com.vultbridge.vault;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.Objects;

/**
 * Encodes and validates public v1 record frames without trusting or authenticating their bodies.
 *
 * <p>Reads are positional and verify the authenticated reference, physical file bounds, exact
 * public ID, and exact public length before returning a header. Bounded-body reads are available
 * only for COMMIT and MANIFEST records; FILE bodies remain streaming-only.
 */
public final class RecordFrameCodec {
  private RecordFrameCodec() {}

  /** Returns the exact 24-byte public header for a caller-validated ID and body length. */
  public static byte[] encodeHeader(RecordFrameHeader header) {
    Objects.requireNonNull(header, "header");
    ByteBuffer output =
        ByteBuffer.allocate(VaultFormat.RECORD_FRAME_HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
    output.put(header.recordId().bytes());
    output.putLong(header.storedLength());
    return output.array();
  }

  /**
   * Reads and verifies one public frame header against an authenticated reference and commit end.
   */
  public static RecordFrameHeader readVerifiedHeader(
      FileChannel channel, RecordRef reference, long authenticatedCommitEnd)
      throws IOException, VaultDataException {
    Objects.requireNonNull(channel, "channel");
    Objects.requireNonNull(reference, "reference");
    reference.requireWithin(authenticatedCommitEnd);
    if (reference.endOffset() > channel.size()) {
      throw new VaultDataException();
    }

    ByteBuffer input = ByteBuffer.allocate(VaultFormat.RECORD_FRAME_HEADER_BYTES);
    readFully(channel, input, reference.offset());
    input.flip();
    byte[] id = new byte[VaultFormat.RECORD_ID_BYTES];
    input.get(id);
    long storedLength = input.getLong();
    if (storedLength < 0
        || !new RecordId(id).equals(reference.recordId())
        || storedLength != reference.storedLength()) {
      throw new VaultDataException();
    }
    return new RecordFrameHeader(reference.recordId(), storedLength);
  }

  /** Reads a complete bounded COMMIT or MANIFEST encrypted body after exact frame verification. */
  public static byte[] readBoundedBody(
      FileChannel channel, RecordRef reference, long authenticatedCommitEnd, int maximumStoredBytes)
      throws IOException, VaultDataException {
    if (maximumStoredBytes < 0
        || reference.expectedRole() == RecordRole.FILE
        || reference.storedLength() > maximumStoredBytes) {
      throw new VaultDataException();
    }
    readVerifiedHeader(channel, reference, authenticatedCommitEnd);
    byte[] body = new byte[Math.toIntExact(reference.storedLength())];
    readFully(
        channel,
        ByteBuffer.wrap(body),
        Math.addExact(reference.offset(), VaultFormat.RECORD_FRAME_HEADER_BYTES));
    return body;
  }

  static void writeFully(FileChannel channel, ByteBuffer source, long offset) throws IOException {
    long position = offset;
    while (source.hasRemaining()) {
      int written = channel.write(source, position);
      if (written <= 0) {
        throw new IOException("Unable to complete vault write");
      }
      position = Math.addExact(position, written);
    }
  }

  private static void readFully(FileChannel channel, ByteBuffer destination, long offset)
      throws IOException, VaultDataException {
    long position = offset;
    while (destination.hasRemaining()) {
      int read = channel.read(destination, position);
      if (read < 0) {
        throw new VaultDataException();
      }
      if (read == 0) {
        throw new VaultDataException();
      }
      position = Math.addExact(position, read);
    }
  }
}
