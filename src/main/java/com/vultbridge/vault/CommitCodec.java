package com.vultbridge.vault;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Encodes and strictly parses the authenticated plaintext of a v1 COMMIT record.
 *
 * <p>The codec uses canonical definite-array CBOR, rejects plaintext above 64 KiB before parsing,
 * and maps every malformed or non-canonical representation to {@link VaultDataException}.
 */
public final class CommitCodec {
  private CommitCodec() {}

  /** Encodes locally validated commit fields into canonical v1 CBOR plaintext. */
  public static byte[] encode(VaultCommit commit) {
    Objects.requireNonNull(commit, "commit");
    try {
      var output = new ByteArrayOutputStream();
      try (var generator = VaultCbor.FACTORY.createGenerator(output)) {
        generator.writeStartArray(null, 6);
        generator.writeNumber(RecordRole.COMMIT.code());
        generator.writeNumber(VaultFormat.RECORD_SCHEMA_VERSION);
        VaultCbor.writeRecordRef(generator, commit.manifestRef());
        generator.writeNumber(commit.committedEnd());
        generator.writeNumber(commit.liveLogicalFileBytes());
        generator.writeNumber(commit.fileCount());
        generator.writeEndArray();
      }
      byte[] encoded = output.toByteArray();
      if (encoded.length > VaultFormat.MAXIMUM_COMMIT_PLAINTEXT_BYTES) {
        throw new IllegalArgumentException("Commit plaintext exceeds the v1 limit");
      }
      return encoded;
    } catch (IOException exception) {
      throw new IllegalStateException("Unable to encode commit", exception);
    }
  }

  /** Parses canonical v1 COMMIT plaintext without yet trusting its manifest relationship. */
  public static VaultCommit decode(byte[] plaintext) throws VaultDataException {
    Objects.requireNonNull(plaintext, "plaintext");
    if (plaintext.length == 0 || plaintext.length > VaultFormat.MAXIMUM_COMMIT_PLAINTEXT_BYTES) {
      throw new VaultDataException();
    }
    try (JsonParser parser = VaultCbor.FACTORY.createParser(plaintext)) {
      VaultCbor.requireNext(parser, JsonToken.START_ARRAY);
      requireExactNumber(parser, RecordRole.COMMIT.code());
      requireExactNumber(parser, VaultFormat.RECORD_SCHEMA_VERSION);
      RecordRef manifestRef = VaultCbor.readRecordRef(parser);
      long committedEnd = VaultCbor.readNonNegativeLong(parser);
      long liveBytes = VaultCbor.readNonNegativeLong(parser);
      int fileCount = Math.toIntExact(VaultCbor.readNonNegativeLong(parser));
      VaultCbor.requireNext(parser, JsonToken.END_ARRAY);
      if (parser.nextToken() != null) {
        throw new VaultDataException();
      }
      VaultCommit commit;
      try {
        commit = new VaultCommit(manifestRef, committedEnd, liveBytes, fileCount);
      } catch (IllegalArgumentException exception) {
        throw new VaultDataException();
      }
      byte[] canonical = encode(commit);
      try {
        if (!Arrays.equals(plaintext, canonical)) {
          throw new VaultDataException();
        }
      } finally {
        Arrays.fill(canonical, (byte) 0);
      }
      return commit;
    } catch (VaultDataException exception) {
      throw exception;
    } catch (IOException | RuntimeException exception) {
      throw new VaultDataException();
    }
  }

  private static void requireExactNumber(JsonParser parser, long expected)
      throws IOException, VaultDataException {
    if (VaultCbor.readNonNegativeLong(parser) != expected) {
      throw new VaultDataException();
    }
  }
}
