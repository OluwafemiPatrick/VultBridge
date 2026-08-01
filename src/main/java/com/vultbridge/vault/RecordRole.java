package com.vultbridge.vault;

/**
 * Identifies the authenticated semantic role of a v1 encrypted record.
 *
 * <p>The numeric code is persisted in references and bound into record associated data. Unknown
 * codes are rejected rather than treated as forward-compatible because v1 parsers are strict.
 */
public enum RecordRole {
  COMMIT(VaultFormat.ROLE_COMMIT),
  MANIFEST(VaultFormat.ROLE_MANIFEST),
  FILE(VaultFormat.ROLE_FILE);

  private final int code;

  RecordRole(int code) {
    this.code = code;
  }

  /** Returns the exact v1 role byte value. */
  public int code() {
    return code;
  }

  /** Resolves a persisted role code or rejects it as invalid vault data. */
  public static RecordRole fromCode(int code) throws VaultDataException {
    for (RecordRole role : values()) {
      if (role.code == code) {
        return role;
      }
    }
    throw new VaultDataException();
  }
}
