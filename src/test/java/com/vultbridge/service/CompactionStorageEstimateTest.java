package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Verifies checked storage-estimate invariants and the explicit preflight margin. */
class CompactionStorageEstimateTest {
  @Test
  void reportsSufficientAndInsufficientUsableSpace() {
    var sufficient = new CompactionStorageEstimate(100, 80, 2, 200, 4, 204, 204);
    var insufficient = new CompactionStorageEstimate(100, 80, 2, 200, 4, 204, 203);

    assertTrue(sufficient.hasSufficientSpace());
    assertFalse(insufficient.hasSufficientSpace());
    assertEquals(204, sufficient.requiredDestinationBytes());
  }

  @Test
  void rejectsInconsistentAndOverflowingRequiredSpace() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new CompactionStorageEstimate(0, 0, 0, 20, 4, 23, 100));
    assertThrows(
        IllegalArgumentException.class,
        () -> new CompactionStorageEstimate(0, 0, 0, Long.MAX_VALUE, 1, 0, Long.MAX_VALUE));
  }
}
