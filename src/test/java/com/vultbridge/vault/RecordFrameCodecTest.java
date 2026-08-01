package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies exact record framing and pre-allocation reference checks. */
class RecordFrameCodecTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final RecordId ID = new RecordId(HEX.parseHex("000102030405060708090a0b0c0d0e0f"));
  @TempDir Path temporaryDirectory;

  @Test
  void headerEncodingMatchesTheLiteralLayout() {
    assertArrayEquals(
        HEX.parseHex("000102030405060708090a0b0c0d0e0f0000000000000003"),
        RecordFrameCodec.encodeHeader(new RecordFrameHeader(ID, 3)));
  }

  @Test
  void verifiesAndReadsAnExactBoundedFrame() throws IOException, VaultDataException {
    byte[] body = {1, 2, 3};
    Path vault = writeFrame(body);
    var reference =
        new RecordRef(ID, VaultFormat.FIXED_HEADER_BYTES, body.length, RecordRole.MANIFEST);
    try (FileChannel channel = FileChannel.open(vault, StandardOpenOption.READ)) {
      assertEquals(
          new RecordFrameHeader(ID, body.length),
          RecordFrameCodec.readVerifiedHeader(channel, reference, reference.endOffset()));
      assertArrayEquals(
          body, RecordFrameCodec.readBoundedBody(channel, reference, reference.endOffset(), 3));
    }
  }

  @Test
  void rejectsMismatchedIdLengthTruncationAndCommitRange() throws IOException {
    byte[] body = {1, 2, 3};
    Path vault = writeFrame(body);
    try (FileChannel channel =
        FileChannel.open(vault, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
      var exact = new RecordRef(ID, VaultFormat.FIXED_HEADER_BYTES, 3, RecordRole.MANIFEST);
      var wrongId =
          new RecordRef(new RecordId(new byte[16]), exact.offset(), 3, RecordRole.MANIFEST);
      var wrongLength = new RecordRef(ID, exact.offset(), 2, RecordRole.MANIFEST);
      assertThrows(
          VaultDataException.class,
          () -> RecordFrameCodec.readVerifiedHeader(channel, wrongId, exact.endOffset()));
      assertThrows(
          VaultDataException.class,
          () -> RecordFrameCodec.readVerifiedHeader(channel, wrongLength, exact.endOffset()));
      assertThrows(
          VaultDataException.class,
          () -> RecordFrameCodec.readVerifiedHeader(channel, exact, exact.endOffset() - 1));

      channel.truncate(exact.endOffset() - 1);
      assertThrows(
          VaultDataException.class,
          () -> RecordFrameCodec.readVerifiedHeader(channel, exact, exact.endOffset()));
    }
  }

  @Test
  void refusesFileOrOversizedBodiesBeforeAllocation() throws IOException {
    Path vault = writeFrame(new byte[] {1, 2, 3});
    try (FileChannel channel = FileChannel.open(vault, StandardOpenOption.READ)) {
      var fileRef = new RecordRef(ID, VaultFormat.FIXED_HEADER_BYTES, 3, RecordRole.FILE);
      var manifestRef = new RecordRef(ID, fileRef.offset(), 3, RecordRole.MANIFEST);
      assertThrows(
          VaultDataException.class,
          () -> RecordFrameCodec.readBoundedBody(channel, fileRef, fileRef.endOffset(), 3));
      assertThrows(
          VaultDataException.class,
          () -> RecordFrameCodec.readBoundedBody(channel, manifestRef, manifestRef.endOffset(), 2));
    }
  }

  private Path writeFrame(byte[] body) throws IOException {
    Path path = temporaryDirectory.resolve("frame.bin");
    byte[] prefix = new byte[VaultFormat.FIXED_HEADER_BYTES];
    byte[] header = RecordFrameCodec.encodeHeader(new RecordFrameHeader(ID, body.length));
    byte[] complete = Arrays.copyOf(prefix, prefix.length + header.length + body.length);
    System.arraycopy(header, 0, complete, prefix.length, header.length);
    System.arraycopy(body, 0, complete, prefix.length + header.length, body.length);
    Files.write(path, complete);
    return path;
  }
}
