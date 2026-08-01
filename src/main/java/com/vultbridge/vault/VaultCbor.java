package com.vultbridge.vault;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import java.io.IOException;

/** Shared strict CBOR primitives for the fixed v1 MANIFEST and COMMIT schemas. */
final class VaultCbor {
  static final CBORFactory FACTORY =
      CBORFactory.builder().enable(CBORGenerator.Feature.WRITE_MINIMAL_INTS).build();

  private VaultCbor() {}

  static void writeRecordRef(JsonGenerator generator, RecordRef reference) throws IOException {
    generator.writeStartArray(null, 4);
    generator.writeBinary(reference.recordId().bytes());
    generator.writeNumber(reference.offset());
    generator.writeNumber(reference.storedLength());
    generator.writeNumber(reference.expectedRole().code());
    generator.writeEndArray();
  }

  static RecordRef readRecordRef(JsonParser parser) throws IOException, VaultDataException {
    requireNext(parser, JsonToken.START_ARRAY);
    requireNext(parser, JsonToken.VALUE_EMBEDDED_OBJECT);
    byte[] recordId = parser.getBinaryValue();
    long offset = readNonNegativeLong(parser);
    long storedLength = readNonNegativeLong(parser);
    int roleCode = Math.toIntExact(readNonNegativeLong(parser));
    requireNext(parser, JsonToken.END_ARRAY);
    try {
      return new RecordRef(
          new RecordId(recordId), offset, storedLength, RecordRole.fromCode(roleCode));
    } catch (IllegalArgumentException exception) {
      throw new VaultDataException();
    }
  }

  static long readNonNegativeLong(JsonParser parser) throws IOException, VaultDataException {
    requireNext(parser, JsonToken.VALUE_NUMBER_INT);
    long value;
    try {
      value = parser.getLongValue();
    } catch (RuntimeException exception) {
      throw new VaultDataException();
    }
    if (value < 0) {
      throw new VaultDataException();
    }
    return value;
  }

  static void requireNext(JsonParser parser, JsonToken expected)
      throws IOException, VaultDataException {
    if (parser.nextToken() != expected) {
      throw new VaultDataException();
    }
  }
}
