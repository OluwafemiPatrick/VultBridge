package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/** Verifies that persisted-data failures cannot retain or surface sensitive parser details. */
class VaultDataExceptionTest {
  @Test
  void exposesOnlyTheApprovedMessageAndNoCause() {
    var exception = new VaultDataException();

    assertEquals("Vault data is invalid", exception.getMessage());
    assertNull(exception.getCause());
  }
}
