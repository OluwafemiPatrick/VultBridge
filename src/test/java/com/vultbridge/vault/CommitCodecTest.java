package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies strict COMMIT CBOR and authenticated cross-record consistency. */
class CommitCodecTest {
  private static final HexFormat HEX = HexFormat.of();

  @Test
  void canonicalCommitRoundTripsAndMatchesItsEmptyManifest() throws VaultDataException {
    VaultManifest manifest = new VaultManifest(List.of());
    RecordRef manifestRef = manifestRef();
    RecordRef commitRef = commitRef(manifestRef.endOffset(), 80);
    var commit = new VaultCommit(manifestRef, commitRef.endOffset(), 0, 0);

    VaultCommit decoded = CommitCodec.decode(CommitCodec.encode(commit));
    decoded.requireConsistentWith(commitRef, manifest);

    assertEquals(commit, decoded);
  }

  @Test
  void rejectsWrongShapeRoleVersionTrailingAndNonCanonicalForms() {
    for (byte[] invalid :
        List.of(
            HEX.parseHex("8101"),
            HEX.parseHex("86020184000000000000"),
            HEX.parseHex("86010284000000000000"),
            HEX.parseHex("9f010184500000000000000000000000000000000019011a10020000ff"))) {
      assertThrows(VaultDataException.class, () -> CommitCodec.decode(invalid));
    }
  }

  @Test
  void rejectsOversizedPlaintextBeforeParsing() {
    assertThrows(
        VaultDataException.class,
        () -> CommitCodec.decode(new byte[VaultFormat.MAXIMUM_COMMIT_PLAINTEXT_BYTES + 1]));
  }

  @Test
  void rejectsWrongCommitEndManifestPositionAndTotals() {
    VaultManifest manifest = new VaultManifest(List.of());
    RecordRef manifestRef = manifestRef();
    RecordRef commitRef = commitRef(manifestRef.endOffset(), 80);
    assertThrows(
        VaultDataException.class,
        () ->
            new VaultCommit(manifestRef, commitRef.endOffset() - 1, 0, 0)
                .requireConsistentWith(commitRef, manifest));
    assertThrows(
        VaultDataException.class,
        () ->
            new VaultCommit(manifestRef, commitRef.endOffset(), 1, 0)
                .requireConsistentWith(commitRef, manifest));
    var overlappingManifest =
        new RecordRef(
            manifestRef.recordId(),
            commitRef.offset(),
            manifestRef.storedLength(),
            RecordRole.MANIFEST);
    assertThrows(
        VaultDataException.class,
        () ->
            new VaultCommit(overlappingManifest, commitRef.endOffset(), 0, 0)
                .requireConsistentWith(commitRef, manifest));
  }

  @Test
  void rejectsManifestFileReferencesBeyondTheAuthenticatedCommitEnd() {
    RecordRef manifestRef = manifestRef();
    RecordRef commitRef = commitRef(manifestRef.endOffset(), 80);
    FileRecordLayout layout = FileRecordLayout.forLogicalSize(1);
    var outsideFileRef =
        new RecordRef(
            id("202122232425262728292a2b2c2d2e2f"),
            commitRef.endOffset(),
            layout.storedLength(),
            RecordRole.FILE);
    var manifest =
        new VaultManifest(
            List.of(
                new ManifestEntry(
                    "outside.txt",
                    outsideFileRef,
                    1,
                    layout.chunkCount(),
                    java.time.Instant.EPOCH)));
    var commit = new VaultCommit(manifestRef, commitRef.endOffset(), 1, 1);

    assertThrows(VaultDataException.class, () -> commit.requireConsistentWith(commitRef, manifest));
  }

  private static RecordRef manifestRef() {
    return new RecordRef(
        id("000102030405060708090a0b0c0d0e0f"),
        VaultFormat.FIXED_HEADER_BYTES,
        20,
        RecordRole.MANIFEST);
  }

  private static RecordRef commitRef(long offset, long length) {
    return new RecordRef(id("101112131415161718191a1b1c1d1e1f"), offset, length, RecordRole.COMMIT);
  }

  private static RecordId id(String hex) {
    return new RecordId(HEX.parseHex(hex));
  }
}
