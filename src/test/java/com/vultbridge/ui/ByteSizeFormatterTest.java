package com.vultbridge.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ByteSizeFormatterTest {
  @Test
  void formatsBytesAndBinaryUnits() {
    assertEquals("0 B", ByteSizeFormatter.format(0));
    assertEquals("1.0 KiB", ByteSizeFormatter.format(1024));
    assertEquals("1.5 MiB", ByteSizeFormatter.format(1572864));
    assertEquals("2.0 GiB", ByteSizeFormatter.format(2147483648L));
  }

  @Test
  void rejectsNegativeByteCount() {
    assertThrows(IllegalArgumentException.class, () -> ByteSizeFormatter.format(-1));
  }
}
