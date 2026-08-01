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
import java.time.Instant;
import java.util.concurrent.CancellationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies authenticated bounded FILE reads and plaintext withholding on tampering. */
class FileRecordReaderTest {
  @TempDir Path temporaryDirectory;

  @Test
  void authenticatesAndStreamsAnExactMultiChunkFile() throws Exception {
    byte[] original = new byte[VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES + 7];
    for (int index = 0; index < original.length; index++) {
      original[index] = (byte) (index * 17);
    }
    Fixture fixture = writeFileRecord(original, "multi.bin");
    Path output = temporaryDirectory.resolve("output.bin");

    try (fixture;
        var destination =
            FileChannel.open(
                output,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE)) {
      assertEquals(
          original.length,
          FileRecordReader.streamTo(
              fixture.vault,
              fixture.keys.keys(),
              fixture.entry,
              fixture.entry.fileRef().endOffset(),
              destination,
              () -> false));
    }

    assertArrayEquals(original, Files.readAllBytes(output));
  }

  @Test
  void tamperedFirstChunkWritesNoPlaintext() throws Exception {
    Fixture fixture = writeFileRecord(new byte[] {1, 2, 3}, "tampered.bin");
    Path output = temporaryDirectory.resolve("tampered-output.bin");
    try (fixture;
        var destination =
            FileChannel.open(
                output,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE)) {
      long tagByte = fixture.entry.fileRef().endOffset() - 1;
      ByteBuffer changed = ByteBuffer.wrap(new byte[] {(byte) 0xff});
      fixture.vault.write(changed, tagByte);

      assertThrows(
          VaultDataException.class,
          () ->
              FileRecordReader.streamTo(
                  fixture.vault,
                  fixture.keys.keys(),
                  fixture.entry,
                  fixture.entry.fileRef().endOffset(),
                  destination,
                  () -> false));
      assertEquals(0, destination.size());
    }
  }

  @Test
  void rejectsOutOfCommitRangeAndCancelsBeforePlaintext() throws Exception {
    Fixture fixture = writeFileRecord(new byte[] {1}, "range.bin");
    try (fixture;
        var destination =
            FileChannel.open(
                temporaryDirectory.resolve("range-output.bin"),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE)) {
      assertThrows(
          VaultDataException.class,
          () ->
              FileRecordReader.streamTo(
                  fixture.vault,
                  fixture.keys.keys(),
                  fixture.entry,
                  fixture.entry.fileRef().endOffset() - 1,
                  destination,
                  () -> false));
      assertThrows(
          CancellationException.class,
          () ->
              FileRecordReader.streamTo(
                  fixture.vault,
                  fixture.keys.keys(),
                  fixture.entry,
                  fixture.entry.fileRef().endOffset(),
                  destination,
                  () -> true));
      assertEquals(0, destination.size());
    }
  }

  private Fixture writeFileRecord(byte[] plaintext, String name) throws Exception {
    Path sourcePath = temporaryDirectory.resolve("source-" + name);
    Files.write(sourcePath, plaintext);
    var keys = keys();
    FileChannel source = FileChannel.open(sourcePath, StandardOpenOption.READ);
    FileChannel vault =
        FileChannel.open(
            temporaryDirectory.resolve(name + ".vault"),
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.READ,
            StandardOpenOption.WRITE);
    try {
      vault.write(ByteBuffer.wrap(new byte[VaultFormat.FIXED_HEADER_BYTES]));
      FileRecordLayout layout = FileRecordLayout.forLogicalSize(plaintext.length);
      RecordRef reference =
          AppendCommitProtocol.forCreation(vault)
              .appendFileRecord(id(8), layout, keys.keys(), source, () -> false);
      return new Fixture(
          keys,
          vault,
          new ManifestEntry(name, reference, plaintext.length, layout.chunkCount(), Instant.EPOCH));
    } catch (Throwable failure) {
      vault.close();
      keys.close();
      throw failure;
    } finally {
      source.close();
    }
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

  private record Fixture(
      com.vultbridge.crypto.CreatedVaultKeySet keys, FileChannel vault, ManifestEntry entry)
      implements AutoCloseable {
    @Override
    public void close() throws java.io.IOException {
      vault.close();
      keys.close();
    }
  }
}
