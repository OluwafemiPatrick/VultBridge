package com.vultbridge.vault;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

/**
 * Encodes and strictly parses the authenticated plaintext of a v1 MANIFEST record.
 *
 * <p>The canonical writer uses definite arrays and minimal non-negative integers. The reader is
 * bounded to 16 MiB, validates exact types and array shapes through the streaming API, enforces all
 * semantic manifest invariants, and rejects any non-canonical alternative by byte-for-byte
 * re-encoding. Plaintext ownership remains with the caller.
 */
public final class ManifestCodec {
  private ManifestCodec() {}

  /** Encodes a validated manifest into canonical v1 CBOR plaintext. */
  public static byte[] encode(VaultManifest manifest) {
    Objects.requireNonNull(manifest, "manifest");
    try {
      var output = new ByteArrayOutputStream();
      try (var generator = VaultCbor.FACTORY.createGenerator(output)) {
        generator.writeStartArray(null, 3);
        generator.writeNumber(RecordRole.MANIFEST.code());
        generator.writeNumber(VaultFormat.RECORD_SCHEMA_VERSION);
        generator.writeStartArray(null, manifest.fileCount());
        for (ManifestEntry entry : manifest.entries()) {
          generator.writeStartArray(null, 5);
          generator.writeString(entry.displayName());
          VaultCbor.writeRecordRef(generator, entry.fileRef());
          generator.writeNumber(entry.logicalSize());
          generator.writeNumber(entry.chunkCount());
          generator.writeNumber(entry.importedAtUtc().toEpochMilli());
          generator.writeEndArray();
        }
        generator.writeEndArray();
        generator.writeEndArray();
      }
      byte[] encoded = output.toByteArray();
      if (encoded.length > VaultFormat.MAXIMUM_MANIFEST_PLAINTEXT_BYTES) {
        throw new IllegalArgumentException("Manifest plaintext exceeds the v1 limit");
      }
      return encoded;
    } catch (IOException exception) {
      throw new IllegalStateException("Unable to encode manifest", exception);
    }
  }

  /** Parses canonical v1 MANIFEST plaintext or returns one sanitized data failure. */
  public static VaultManifest decode(byte[] plaintext) throws VaultDataException {
    Objects.requireNonNull(plaintext, "plaintext");
    if (plaintext.length == 0 || plaintext.length > VaultFormat.MAXIMUM_MANIFEST_PLAINTEXT_BYTES) {
      throw new VaultDataException();
    }
    try (JsonParser parser = VaultCbor.FACTORY.createParser(plaintext)) {
      VaultCbor.requireNext(parser, JsonToken.START_ARRAY);
      requireExactNumber(parser, RecordRole.MANIFEST.code());
      requireExactNumber(parser, VaultFormat.RECORD_SCHEMA_VERSION);
      VaultCbor.requireNext(parser, JsonToken.START_ARRAY);

      var entries = new ArrayList<ManifestEntry>();
      while (parser.nextToken() != JsonToken.END_ARRAY) {
        if (parser.currentToken() != JsonToken.START_ARRAY
            || entries.size() == VaultFormat.MAXIMUM_FILE_COUNT) {
          throw new VaultDataException();
        }
        VaultCbor.requireNext(parser, JsonToken.VALUE_STRING);
        String displayName = parser.getText();
        RecordRef fileRef = VaultCbor.readRecordRef(parser);
        long logicalSize = VaultCbor.readNonNegativeLong(parser);
        long chunkCount = VaultCbor.readNonNegativeLong(parser);
        long importedAtEpochMillis = VaultCbor.readNonNegativeLong(parser);
        VaultCbor.requireNext(parser, JsonToken.END_ARRAY);
        try {
          entries.add(
              new ManifestEntry(
                  displayName,
                  fileRef,
                  logicalSize,
                  chunkCount,
                  Instant.ofEpochMilli(importedAtEpochMillis)));
        } catch (IllegalArgumentException exception) {
          throw new VaultDataException();
        }
      }
      VaultCbor.requireNext(parser, JsonToken.END_ARRAY);
      if (parser.nextToken() != null) {
        throw new VaultDataException();
      }
      VaultManifest manifest;
      try {
        manifest = new VaultManifest(entries);
      } catch (IllegalArgumentException | ArithmeticException exception) {
        throw new VaultDataException();
      }
      // This comparison rejects indefinite arrays, wider-than-minimal integers, tags, and any
      // other alternate byte representation while leaving structural parsing to Jackson.
      if (!Arrays.equals(plaintext, encode(manifest))) {
        throw new VaultDataException();
      }
      return manifest;
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
