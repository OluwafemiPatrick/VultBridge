package com.vultbridge.vault;

/**
 * Computes the canonical v1 encrypted FILE-body layout from an authenticated logical size.
 *
 * <p>The layout enforces the 100 GiB policy cap, one authenticated chunk for an empty file, the 4
 * MiB plaintext chunk size, one 16-byte tag per chunk, and checked arithmetic. It contains no file
 * content and performs no I/O.
 */
public final class FileRecordLayout {
  private final long logicalSize;
  private final long chunkCount;
  private final long storedLength;

  private FileRecordLayout(long logicalSize, long chunkCount, long storedLength) {
    this.logicalSize = logicalSize;
    this.chunkCount = chunkCount;
    this.storedLength = storedLength;
  }

  /** Computes the unique valid v1 layout for a logical file size. */
  public static FileRecordLayout forLogicalSize(long logicalSize) {
    if (logicalSize < 0 || logicalSize > VaultFormat.MAXIMUM_LIVE_FILE_BYTES) {
      throw new IllegalArgumentException("Logical file size is outside the v1 range");
    }
    long chunks =
        logicalSize == 0
            ? 1
            : Math.floorDiv(logicalSize - 1, VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES) + 1;
    if (chunks > 0xffff_ffffL) {
      throw new IllegalArgumentException("FILE chunk count exceeds u32");
    }
    long tags = Math.multiplyExact(chunks, VaultFormat.AEAD_TAG_BYTES);
    return new FileRecordLayout(logicalSize, chunks, Math.addExact(logicalSize, tags));
  }

  /** Returns the authenticated logical plaintext size. */
  public long logicalSize() {
    return logicalSize;
  }

  /** Returns the canonical nonzero chunk count. */
  public long chunkCount() {
    return chunkCount;
  }

  /** Returns the exact encrypted-body length, including one tag per chunk. */
  public long storedLength() {
    return storedLength;
  }

  /** Returns the exact plaintext length of one chunk. */
  public int chunkPlaintextLength(long chunkIndex) {
    requireChunkIndex(chunkIndex);
    if (logicalSize == 0) {
      return 0;
    }
    if (chunkIndex < chunkCount - 1) {
      return VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES;
    }
    long preceding =
        Math.multiplyExact(chunkCount - 1, (long) VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES);
    return Math.toIntExact(logicalSize - preceding);
  }

  /** Returns the encrypted-body-relative offset of one chunk's ciphertext. */
  public long chunkStoredOffset(long chunkIndex) {
    requireChunkIndex(chunkIndex);
    long fullStoredChunk =
        Math.addExact(VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES, VaultFormat.AEAD_TAG_BYTES);
    return Math.multiplyExact(chunkIndex, fullStoredChunk);
  }

  private void requireChunkIndex(long chunkIndex) {
    if (chunkIndex < 0 || chunkIndex >= chunkCount) {
      throw new IllegalArgumentException("Chunk index is outside this FILE layout");
    }
  }
}
