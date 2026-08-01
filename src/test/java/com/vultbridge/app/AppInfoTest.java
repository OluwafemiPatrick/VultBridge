package com.vultbridge.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class AppInfoTest {
  @Test
  void exposesStableApplicationMetadata() {
    assertEquals("VultBridge", AppInfo.NAME);
    assertFalse(AppInfo.VERSION.isBlank());
  }
}
