package com.vultbridge.app;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AppInfoTest {
  @Test
  void exposesStableApplicationMetadata() {
    assertEquals("VultBridge", AppInfo.NAME);
  }
}
