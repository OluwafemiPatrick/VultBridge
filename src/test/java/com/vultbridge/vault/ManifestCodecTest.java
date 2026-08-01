package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies canonical streaming CBOR and strict MANIFEST rejection behavior. */
class ManifestCodecTest {
  private static final HexFormat HEX = HexFormat.of();

  @Test
  void emptyManifestMatchesTheCanonicalLiteral() throws VaultDataException {
    byte[] expected = HEX.parseHex("83020180");
    assertArrayEquals(expected, ManifestCodec.encode(new VaultManifest(List.of())));
    assertEquals(0, ManifestCodec.decode(expected).fileCount());
  }

  @Test
  void populatedManifestRoundTripsEveryField() throws VaultDataException {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(5);
    var reference =
        new RecordRef(
            new RecordId(HEX.parseHex("000102030405060708090a0b0c0d0e0f")),
            VaultFormat.FIXED_HEADER_BYTES,
            layout.storedLength(),
            RecordRole.FILE);
    var original =
        new VaultManifest(
            List.of(
                new ManifestEntry(
                    "résumé.txt", reference, 5, layout.chunkCount(), Instant.ofEpochMilli(1234))));

    VaultManifest decoded = ManifestCodec.decode(ManifestCodec.encode(original));

    assertEquals(1, decoded.fileCount());
    assertEquals("résumé.txt", decoded.entries().getFirst().displayName());
    assertEquals(reference, decoded.entries().getFirst().fileRef());
    assertEquals(Instant.ofEpochMilli(1234), decoded.entries().getFirst().importedAtUtc());
  }

  @Test
  void rejectsWrongShapeTypeRoleVersionTrailingAndNonCanonicalForms() {
    for (byte[] invalid :
        List.of(
            HEX.parseHex("820201"),
            HEX.parseHex("836201800180"),
            HEX.parseHex("83010180"),
            HEX.parseHex("83020280"),
            HEX.parseHex("8302018000"),
            HEX.parseHex("8318020180"),
            HEX.parseHex("9f020180ff"))) {
      assertThrows(VaultDataException.class, () -> ManifestCodec.decode(invalid));
    }
  }

  @Test
  void rejectsEmptyAndOversizedPlaintextBeforeParsing() {
    assertThrows(VaultDataException.class, () -> ManifestCodec.decode(new byte[0]));
    assertThrows(
        VaultDataException.class,
        () -> ManifestCodec.decode(new byte[VaultFormat.MAXIMUM_MANIFEST_PLAINTEXT_BYTES + 1]));
  }

  @Test
  void timestampMustBeRepresentableAsNonNegativeEpochMilliseconds() {
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(0);
    var reference =
        new RecordRef(
            new RecordId(new byte[16]),
            VaultFormat.FIXED_HEADER_BYTES,
            layout.storedLength(),
            RecordRole.FILE);
    assertThrows(
        IllegalArgumentException.class,
        () -> new ManifestEntry("file", reference, 0, 1, Instant.ofEpochMilli(-1)));
  }

  @Test
  void decoderDoesNotModifyCallerPlaintext() throws VaultDataException {
    byte[] plaintext = ManifestCodec.encode(new VaultManifest(List.of()));
    byte[] original = Arrays.copyOf(plaintext, plaintext.length);
    ManifestCodec.decode(plaintext);
    assertArrayEquals(original, plaintext);
  }
}
