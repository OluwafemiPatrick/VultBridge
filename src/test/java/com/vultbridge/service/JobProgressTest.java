package com.vultbridge.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class JobProgressTest {
  @Test
  void calculatesFractionComplete() {
    assertEquals(0.25, new JobProgress(JobPhase.PROCESSING, 1, 4).fractionComplete());
    assertEquals(0, new JobProgress(JobPhase.PREPARING, 0, 0).fractionComplete());
  }

  @Test
  void rejectsInvalidProgressRanges() {
    assertThrows(IllegalArgumentException.class, () -> new JobProgress(JobPhase.PROCESSING, -1, 4));
    assertThrows(IllegalArgumentException.class, () -> new JobProgress(JobPhase.PROCESSING, 5, 4));
  }
}
