package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.vultbridge.crypto.PassphraseEncoding;
import com.vultbridge.crypto.V1KeyHierarchy;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies bounded streaming encryption and exact FILE framing. */
class FileRecordStreamingTest {
  @TempDir Path temporaryDirectory;

  @Test
  void streamsMultipleChunksAndAuthenticatesEachExactPlaintext() throws Exception {
    int length = VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES + 3;
    byte[] original = new byte[length];
    for (int index = 0; index < original.length; index++) {
      original[index] = (byte) (index * 31);
    }
    Path sourcePath = temporaryDirectory.resolve("source.bin");
    Files.write(sourcePath, original);
    Path vaultPath = temporaryDirectory.resolve("stream.vltb");
    RecordId recordId = id(1);
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(length);

    try (var createdKeys = keys();
        var source = FileChannel.open(sourcePath, StandardOpenOption.READ);
        var vault = newVaultChannel(vaultPath)) {
      RecordRef reference =
          AppendCommitProtocol.forCreation(vault)
              .appendFileRecord(recordId, layout, createdKeys.keys(), source, () -> false);

      assertEquals(RecordRole.FILE, reference.expectedRole());
      assertEquals(layout.storedLength(), reference.storedLength());
      assertEquals(
          new RecordFrameHeader(recordId, layout.storedLength()),
          RecordFrameCodec.readVerifiedHeader(vault, reference, reference.endOffset()));

      byte[] reconstructed = new byte[length];
      int outputOffset = 0;
      for (long chunk = 0; chunk < layout.chunkCount(); chunk++) {
        int plaintextLength = layout.chunkPlaintextLength(chunk);
        int encryptedLength = plaintextLength + VaultFormat.AEAD_TAG_BYTES;
        byte[] encrypted =
            read(
                vault,
                reference.offset()
                    + VaultFormat.RECORD_FRAME_HEADER_BYTES
                    + layout.chunkStoredOffset(chunk),
                encryptedLength);
        try (var plaintext =
            RecordCrypto.decryptFileChunk(createdKeys.keys(), recordId, layout, chunk, encrypted)) {
          byte[] copy = plaintext.copy();
          System.arraycopy(copy, 0, reconstructed, outputOffset, copy.length);
          java.util.Arrays.fill(copy, (byte) 0);
          outputOffset += plaintextLength;
        }
      }
      assertArrayEquals(original, reconstructed);
    }
  }

  @Test
  void emptyFileWritesOneAuthenticatedTag() throws Exception {
    Path sourcePath = temporaryDirectory.resolve("empty.bin");
    Files.createFile(sourcePath);
    Path vaultPath = temporaryDirectory.resolve("empty.vltb");
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(0);

    try (var createdKeys = keys();
        var source = FileChannel.open(sourcePath, StandardOpenOption.READ);
        var vault = newVaultChannel(vaultPath)) {
      RecordRef reference =
          AppendCommitProtocol.forCreation(vault)
              .appendFileRecord(id(2), layout, createdKeys.keys(), source, () -> false);

      assertEquals(VaultFormat.AEAD_TAG_BYTES, reference.storedLength());
      assertEquals(reference.endOffset(), vault.size());
    }
  }

  @Test
  void cancellationAtChunkBoundaryLeavesNoCompletedRecordState() throws Exception {
    Path sourcePath = temporaryDirectory.resolve("cancel.bin");
    try (var source =
        FileChannel.open(
            sourcePath,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.READ,
            StandardOpenOption.WRITE)) {
      source.position(VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES);
      source.write(ByteBuffer.wrap(new byte[] {1}));
    }
    var checks = new AtomicInteger();
    try (var createdKeys = keys();
        var source = FileChannel.open(sourcePath, StandardOpenOption.READ);
        var vault = newVaultChannel(temporaryDirectory.resolve("cancel.vltb"))) {
      var protocol = AppendCommitProtocol.forCreation(vault);
      assertThrows(
          CancellationException.class,
          () ->
              protocol.appendFileRecord(
                  id(3),
                  FileRecordLayout.forLogicalSize(Files.size(sourcePath)),
                  createdKeys.keys(),
                  source,
                  () -> checks.incrementAndGet() > 1));
      assertThrows(IllegalStateException.class, protocol::forceAppendedRecords);
    }
  }

  private FileChannel newVaultChannel(Path path) throws Exception {
    FileChannel channel =
        FileChannel.open(
            path, StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE);
    channel.write(ByteBuffer.wrap(new byte[VaultFormat.FIXED_HEADER_BYTES]));
    return channel;
  }

  private static byte[] read(FileChannel channel, long offset, int length) throws Exception {
    ByteBuffer output = ByteBuffer.allocate(length);
    while (output.hasRemaining()) {
      int read = channel.read(output, offset + output.position());
      if (read <= 0) {
        throw new IllegalStateException("Unexpected test EOF");
      }
    }
    return output.array();
  }

  private static com.vultbridge.crypto.CreatedVaultKeySet keys() {
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray())) {
      return V1KeyHierarchy.create(passphrase);
    }
  }

  private static RecordId id(int marker) {
    byte[] bytes = new byte[VaultFormat.RECORD_ID_BYTES];
    bytes[bytes.length - 1] = (byte) marker;
    return new RecordId(bytes);
  }
}
