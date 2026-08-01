package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** Verifies exact FILE chunk counts, lengths, offsets, and policy boundaries. */
class FileRecordLayoutTest {
  @Test
  void emptyFileHasOneAuthenticatedZeroByteChunk() {
    var layout = FileRecordLayout.forLogicalSize(0);
    assertEquals(1, layout.chunkCount());
    assertEquals(VaultFormat.AEAD_TAG_BYTES, layout.storedLength());
    assertEquals(0, layout.chunkPlaintextLength(0));
    assertEquals(0, layout.chunkStoredOffset(0));
  }

  @Test
  void computesExactBoundaryAndPartialChunkLayouts() {
    long chunk = VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES;
    var exact = FileRecordLayout.forLogicalSize(chunk);
    var partial = FileRecordLayout.forLogicalSize(chunk + 1);

    assertEquals(1, exact.chunkCount());
    assertEquals(chunk + 16, exact.storedLength());
    assertEquals(chunk, exact.chunkPlaintextLength(0));
    assertEquals(2, partial.chunkCount());
    assertEquals(chunk + 1 + 32, partial.storedLength());
    assertEquals(chunk, partial.chunkPlaintextLength(0));
    assertEquals(1, partial.chunkPlaintextLength(1));
    assertEquals(chunk + 16, partial.chunkStoredOffset(1));
  }

  @Test
  void acceptsTheMaximumAndRejectsValuesOutsideThePolicy() {
    var maximum = FileRecordLayout.forLogicalSize(VaultFormat.MAXIMUM_LIVE_FILE_BYTES);
    assertEquals(25_600, maximum.chunkCount());
    assertEquals(VaultFormat.MAXIMUM_LIVE_FILE_BYTES + (25_600L * 16), maximum.storedLength());
    assertThrows(IllegalArgumentException.class, () -> FileRecordLayout.forLogicalSize(-1));
    assertThrows(
        IllegalArgumentException.class,
        () -> FileRecordLayout.forLogicalSize(VaultFormat.MAXIMUM_LIVE_FILE_BYTES + 1));
  }

  @Test
  void rejectsChunkIndicesOutsideTheComputedLayout() {
    var layout = FileRecordLayout.forLogicalSize(1);
    assertThrows(IllegalArgumentException.class, () -> layout.chunkPlaintextLength(-1));
    assertThrows(IllegalArgumentException.class, () -> layout.chunkStoredOffset(1));
  }
}
