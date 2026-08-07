package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import com.vultbridge.crypto.Argon2idParameters;
import com.vultbridge.crypto.WrappedMasterKey;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs deterministic bounded mutation corpora against the fixed-header, CBOR, framing, and layout
 * boundaries.
 *
 * <p>This is a regression fuzz harness, not a claim of complete parser coverage. It keeps all seeds
 * synthetic, bounds input sizes and iterations, and requires malformed data to become the parser's
 * fixed checked failure rather than an unchecked exception or resource exhaustion.
 */
class FormatFuzzRegressionTest {
  private static final int MUTATION_CASES = 512;
  private static final int MAX_MUTATIONS_PER_CASE = 8;

  @TempDir Path temporaryDirectory;

  @Test
  void fixedHeaderMutationCorpusHasOnlyTheSanitizedParseOutcome() {
    byte[] seed = validHeader();
    var random = new SplittableRandom(0x564c544246555a31L);

    for (int caseIndex = 0; caseIndex < MUTATION_CASES; caseIndex++) {
      int length = random.nextInt(seed.length + 33);
      byte[] candidate = Arrays.copyOf(seed, length);
      mutate(candidate, random);
      assertDoesNotThrow(() -> parseHeaderSafely(candidate));
    }
  }

  @Test
  void manifestAndCommitMutationCorpusHasOnlyCheckedDataFailures() {
    byte[] manifest = ManifestCodec.encode(validManifest());
    RecordRef manifestRef =
        new RecordRef(
            new RecordId(new byte[VaultFormat.RECORD_ID_BYTES]),
            VaultFormat.FIXED_HEADER_BYTES,
            20,
            RecordRole.MANIFEST);
    RecordRef commitRef =
        new RecordRef(
            new RecordId(new byte[VaultFormat.RECORD_ID_BYTES]),
            manifestRef.endOffset(),
            80,
            RecordRole.COMMIT);
    byte[] commit = CommitCodec.encode(new VaultCommit(manifestRef, commitRef.endOffset(), 0, 0));
    var random = new SplittableRandom(0x564c544243424f52L);

    for (int caseIndex = 0; caseIndex < MUTATION_CASES; caseIndex++) {
      byte[] manifestCandidate = Arrays.copyOf(manifest, random.nextInt(manifest.length + 9));
      mutate(manifestCandidate, random);
      assertDoesNotThrow(() -> decodeManifestSafely(manifestCandidate));

      byte[] commitCandidate = Arrays.copyOf(commit, random.nextInt(commit.length + 9));
      mutate(commitCandidate, random);
      assertDoesNotThrow(() -> decodeCommitSafely(commitCandidate));
    }
  }

  @Test
  void boundedRandomCborInputsHaveOnlyTheSanitizedDataFailure() {
    var random = new SplittableRandom(0x564c544243524157L);
    for (int caseIndex = 0; caseIndex < MUTATION_CASES; caseIndex++) {
      byte[] candidate = new byte[random.nextInt(257)];
      random.nextBytes(candidate);
      assertDoesNotThrow(() -> decodeManifestSafely(candidate));
      assertDoesNotThrow(() -> decodeCommitSafely(candidate));
    }
  }

  @Test
  void recordFrameMutationCorpusHasOnlyCheckedIoOrDataOutcomes() throws IOException {
    RecordId id = new RecordId(new byte[VaultFormat.RECORD_ID_BYTES]);
    RecordRef reference = new RecordRef(id, VaultFormat.FIXED_HEADER_BYTES, 3, RecordRole.MANIFEST);
    byte[] validFrame = RecordFrameCodec.encodeHeader(new RecordFrameHeader(id, 3));
    byte[] fileBytes = new byte[Math.toIntExact(reference.endOffset())];
    System.arraycopy(
        validFrame, 0, fileBytes, Math.toIntExact(reference.offset()), validFrame.length);
    fileBytes[Math.toIntExact(reference.offset()) + validFrame.length] = 1;
    Path path = temporaryDirectory.resolve("frame-fuzz.vault");
    Files.write(path, fileBytes);

    var random = new SplittableRandom(0x564c54424652414dL);
    try (FileChannel channel =
        FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
      for (int caseIndex = 0; caseIndex < MUTATION_CASES; caseIndex++) {
        int length = random.nextInt(validFrame.length + 17);
        byte[] candidate = Arrays.copyOf(validFrame, length);
        mutate(candidate, random);
        assertDoesNotThrow(() -> readFrameSafely(channel, reference, candidate));
      }
    }
  }

  @Test
  void fileLayoutBoundaryCorpusHasOnlyTheExpectedRejectedRange() {
    long[] boundaries = {
      -1,
      0,
      1,
      VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES - 1L,
      VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES,
      VaultFormat.FILE_CHUNK_PLAINTEXT_BYTES + 1L,
      VaultFormat.MAXIMUM_LIVE_FILE_BYTES - 1,
      VaultFormat.MAXIMUM_LIVE_FILE_BYTES,
      VaultFormat.MAXIMUM_LIVE_FILE_BYTES + 1
    };
    for (long boundary : boundaries) {
      assertDoesNotThrow(() -> inspectLayoutSafely(boundary));
    }

    var random = new SplittableRandom(0x564c54424c41594fL);
    for (int caseIndex = 0; caseIndex < MUTATION_CASES; caseIndex++) {
      long candidate = random.nextLong(-1_000, VaultFormat.MAXIMUM_LIVE_FILE_BYTES + 1_000);
      assertDoesNotThrow(() -> inspectLayoutSafely(candidate));
    }
  }

  @Test
  void recordReferenceBoundaryCorpusHasOnlyTheExpectedRangeFailure() {
    long[] boundaries = {
      Long.MIN_VALUE,
      -1,
      VaultFormat.FIXED_HEADER_BYTES - 1L,
      VaultFormat.FIXED_HEADER_BYTES,
      VaultFormat.FIXED_HEADER_BYTES + 1L,
      Long.MAX_VALUE - VaultFormat.RECORD_FRAME_HEADER_BYTES - 1L,
      Long.MAX_VALUE
    };
    for (long offset : boundaries) {
      for (long storedLength : boundaries) {
        assertDoesNotThrow(() -> inspectReferenceSafely(offset, storedLength, offset));
      }
    }

    var random = new SplittableRandom(0x564c54425245464cL);
    for (int caseIndex = 0; caseIndex < MUTATION_CASES; caseIndex++) {
      long offset = random.nextLong();
      long storedLength = random.nextLong();
      long committedEnd = random.nextLong();
      assertDoesNotThrow(() -> inspectReferenceSafely(offset, storedLength, committedEnd));
    }
  }

  @Test
  void randomBoundedByteInputsDoNotEscapeTheHeaderFailureContract() {
    var random = new SplittableRandom(0x564c544252414e44L);
    for (int caseIndex = 0; caseIndex < MUTATION_CASES; caseIndex++) {
      byte[] candidate = new byte[random.nextInt(VaultFormat.FIXED_HEADER_BYTES + 33)];
      random.nextBytes(candidate);
      assertDoesNotThrow(() -> parseHeaderSafely(candidate));
    }
  }

  private static void parseHeaderSafely(byte[] candidate) {
    try {
      FixedHeaderCodec.parse(candidate);
    } catch (HeaderParsingException expected) {
      // Every malformed header is intentionally represented by one sanitized checked failure.
    }
  }

  private static void decodeManifestSafely(byte[] candidate) {
    try {
      ManifestCodec.decode(candidate);
    } catch (VaultDataException expected) {
      // Mutation failures must not cross the parser boundary with attacker-controlled details.
    }
  }

  private static void decodeCommitSafely(byte[] candidate) {
    try {
      CommitCodec.decode(candidate);
    } catch (VaultDataException expected) {
      // Mutation failures must not cross the parser boundary with attacker-controlled details.
    }
  }

  private static void readFrameSafely(FileChannel channel, RecordRef reference, byte[] candidate)
      throws IOException {
    byte[] header = Arrays.copyOf(candidate, VaultFormat.RECORD_FRAME_HEADER_BYTES);
    RecordFrameCodec.writeFully(channel, ByteBuffer.wrap(header), reference.offset());
    try {
      RecordFrameCodec.readVerifiedHeader(channel, reference, reference.endOffset());
    } catch (VaultDataException expected) {
      // Invalid IDs, lengths, truncation, and range failures stay within the checked data boundary.
    }
  }

  private static void inspectLayoutSafely(long logicalSize) {
    try {
      FileRecordLayout layout = FileRecordLayout.forLogicalSize(logicalSize);
      layout.chunkPlaintextLength(0);
      layout.chunkStoredOffset(0);
      layout.chunkPlaintextLength(layout.chunkCount() - 1);
      layout.chunkStoredOffset(layout.chunkCount() - 1);
    } catch (IllegalArgumentException expected) {
      // Values outside the authenticated v1 logical-size policy are rejected before arithmetic use.
    }
  }

  private static void inspectReferenceSafely(
      long offset, long storedLength, long authenticatedCommitEnd) {
    try {
      var reference =
          new RecordRef(
              new RecordId(new byte[VaultFormat.RECORD_ID_BYTES]),
              offset,
              storedLength,
              RecordRole.FILE);
      try {
        reference.requireWithin(authenticatedCommitEnd);
      } catch (VaultDataException expected) {
        // An authenticated commit boundary can reject an otherwise structurally valid reference.
      }
    } catch (IllegalArgumentException expected) {
      // Negative, header-overlapping, and overflowing references are rejected before file access.
    }
  }

  private static void mutate(byte[] candidate, SplittableRandom random) {
    if (candidate.length == 0) {
      return;
    }
    int mutations = 1 + random.nextInt(MAX_MUTATIONS_PER_CASE);
    for (int mutation = 0; mutation < mutations; mutation++) {
      int offset = random.nextInt(candidate.length);
      candidate[offset] ^= (byte) (1 + random.nextInt(255));
    }
  }

  private static byte[] validHeader() {
    var envelope =
        new WrappedMasterKey(
            new byte[VaultFormat.VAULT_ID_BYTES],
            Argon2idParameters.creationDefaults(),
            new byte[VaultFormat.KDF_SALT_BYTES],
            new byte[VaultFormat.AEAD_NONCE_BYTES],
            new byte[VaultFormat.WRAPPED_MASTER_VAULT_KEY_BYTES]);
    var slotA =
        new UnverifiedHeaderSlot(
            0,
            0,
            new byte[VaultFormat.RECORD_ID_BYTES],
            VaultFormat.FIXED_HEADER_BYTES,
            80,
            new byte[VaultFormat.HMAC_SHA256_BYTES]);
    var slotB =
        new UnverifiedHeaderSlot(
            1,
            0,
            new byte[VaultFormat.RECORD_ID_BYTES],
            VaultFormat.FIXED_HEADER_BYTES,
            80,
            new byte[VaultFormat.HMAC_SHA256_BYTES]);
    return FixedHeaderCodec.encode(new UnverifiedFixedHeader(envelope, slotA, slotB));
  }

  private static VaultManifest validManifest() {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(4);
    RecordRef fileRef =
        new RecordRef(
            new RecordId(new byte[VaultFormat.RECORD_ID_BYTES]),
            VaultFormat.FIXED_HEADER_BYTES,
            layout.storedLength(),
            RecordRole.FILE);
    return new VaultManifest(
        List.of(new ManifestEntry("sample.bin", fileRef, 4, layout.chunkCount(), Instant.EPOCH)));
  }
}
