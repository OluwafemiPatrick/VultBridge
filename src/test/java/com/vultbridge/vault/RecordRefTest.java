package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** Verifies reference construction and authenticated-range checks before record access. */
class RecordRefTest {
  private static final RecordId ID = new RecordId(new byte[VaultFormat.RECORD_ID_BYTES]);

  @Test
  void acceptsAFrameThatExactlyEndsAtTheCommitBoundary() throws VaultDataException {
    var reference = new RecordRef(ID, VaultFormat.FIXED_HEADER_BYTES, 64, RecordRole.MANIFEST);
    long expectedEnd = VaultFormat.FIXED_HEADER_BYTES + 24L + 64L;

    reference.requireWithin(expectedEnd);

    assertEquals(expectedEnd, reference.endOffset());
  }

  @Test
  void rejectsHeaderOverlapNegativeValuesAndOverflow() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RecordRef(ID, VaultFormat.FIXED_HEADER_BYTES - 1L, 0, RecordRole.COMMIT));
    assertThrows(
        IllegalArgumentException.class,
        () -> new RecordRef(ID, VaultFormat.FIXED_HEADER_BYTES, -1, RecordRole.COMMIT));
    assertThrows(
        IllegalArgumentException.class,
        () -> new RecordRef(ID, Long.MAX_VALUE, 1, RecordRole.COMMIT));
  }

  @Test
  void rejectsRangesOutsideTheAuthenticatedCommit() {
    var reference = new RecordRef(ID, VaultFormat.FIXED_HEADER_BYTES, 64, RecordRole.MANIFEST);
    assertThrows(
        VaultDataException.class, () -> reference.requireWithin(reference.endOffset() - 1));
    assertThrows(VaultDataException.class, () -> reference.requireWithin(-1));
  }
}
