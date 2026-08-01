package com.vultbridge.vault;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Represents the complete authenticated flat v1 manifest.
 *
 * <p>Construction defensively copies at most 10,000 entries, rejects duplicate case-sensitive
 * display names, and calculates the live logical total with checked arithmetic under the 100 GiB
 * policy cap. The manifest contains metadata only and is safe to expose after the full unlock trust
 * order succeeds.
 */
public final class VaultManifest {
  private final List<ManifestEntry> entries;
  private final long liveLogicalFileBytes;

  /** Validates and copies one complete flat manifest. */
  public VaultManifest(List<ManifestEntry> entries) {
    Objects.requireNonNull(entries, "entries");
    if (entries.size() > VaultFormat.MAXIMUM_FILE_COUNT) {
      throw new IllegalArgumentException("Manifest exceeds the file-count limit");
    }
    this.entries = List.copyOf(entries);

    Set<String> names = new HashSet<>();
    long liveBytes = 0;
    for (ManifestEntry entry : this.entries) {
      Objects.requireNonNull(entry, "entry");
      if (!names.add(entry.displayName())) {
        throw new IllegalArgumentException("Manifest contains a duplicate display name");
      }
      liveBytes = Math.addExact(liveBytes, entry.logicalSize());
      if (liveBytes > VaultFormat.MAXIMUM_LIVE_FILE_BYTES) {
        throw new IllegalArgumentException("Manifest exceeds the live-data limit");
      }
    }
    liveLogicalFileBytes = liveBytes;
  }

  /** Returns an immutable metadata-entry list. */
  public List<ManifestEntry> entries() {
    return entries;
  }

  /** Returns the checked sum of all logical FILE sizes. */
  public long liveLogicalFileBytes() {
    return liveLogicalFileBytes;
  }

  /** Returns the authenticated number of flat entries. */
  public int fileCount() {
    return entries.size();
  }
}
