package com.vultbridge.vault;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.time.Instant;
import java.util.Objects;

/**
 * Represents one authenticated flat MANIFEST entry after strict semantic validation.
 *
 * <p>The display name is normalized NFC metadata, never a host path. The FILE reference, logical
 * size, and chunk count must describe one exact canonical {@link FileRecordLayout}. This immutable
 * type contains metadata only and no file content or key material.
 */
public record ManifestEntry(
    String displayName,
    RecordRef fileRef,
    long logicalSize,
    long chunkCount,
    Instant importedAtUtc) {
  public ManifestEntry {
    validateDisplayName(displayName);
    Objects.requireNonNull(fileRef, "fileRef");
    Objects.requireNonNull(importedAtUtc, "importedAtUtc");
    try {
      if (importedAtUtc.toEpochMilli() < 0) {
        throw new IllegalArgumentException("Import timestamp predates the v1 epoch");
      }
    } catch (ArithmeticException exception) {
      throw new IllegalArgumentException("Import timestamp is outside the v1 range", exception);
    }
    if (fileRef.expectedRole() != RecordRole.FILE) {
      throw new IllegalArgumentException("Manifest entry must reference a FILE record");
    }

    FileRecordLayout layout = FileRecordLayout.forLogicalSize(logicalSize);
    if (chunkCount != layout.chunkCount() || fileRef.storedLength() != layout.storedLength()) {
      throw new IllegalArgumentException("Manifest FILE metadata is inconsistent");
    }
  }

  private static void validateDisplayName(String displayName) {
    Objects.requireNonNull(displayName, "displayName");
    if (displayName.isEmpty()
        || displayName.equals(".")
        || displayName.equals("..")
        || !Normalizer.isNormalized(displayName, Normalizer.Form.NFC)
        || displayName.getBytes(StandardCharsets.UTF_8).length
            > VaultFormat.MAXIMUM_DISPLAY_NAME_UTF8_BYTES) {
      throw new IllegalArgumentException("Display name is invalid");
    }
    for (int index = 0; index < displayName.length(); ) {
      int codePoint = displayName.codePointAt(index);
      // A valid surrogate pair becomes one supplementary code point. A remaining surrogate value
      // is therefore unpaired and cannot be represented as the required UTF-8 metadata.
      if (codePoint == '/'
          || codePoint == '\\'
          || Character.isISOControl(codePoint)
          || (codePoint >= Character.MIN_SURROGATE && codePoint <= Character.MAX_SURROGATE)) {
        throw new IllegalArgumentException("Display name is invalid");
      }
      index += Character.charCount(codePoint);
    }
  }
}
