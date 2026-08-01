package com.vultbridge.ui;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Objects;
import java.util.function.IntSupplier;
import java.util.regex.Pattern;

/**
 * Produces the human-readable timestamped filename required by Compact &amp; Replace.
 *
 * <p>Dependencies on time and randomness are supplied as arguments, making naming deterministic in
 * tests. A prior compaction suffix is removed so repeated compactions do not grow the base name.
 */
public final class CompactionNameGenerator {
  private static final Pattern PRIOR_COMPACTION_SUFFIX =
      Pattern.compile("-\\d{8}T\\d{6}Z-[0-9a-f]{6}$");
  private static final DateTimeFormatter TIMESTAMP =
      DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);

  private CompactionNameGenerator() {}

  /** Creates a UTC timestamped {@code .vltb} name with a six-digit hexadecimal collision suffix. */
  public static String generate(
      String vaultDisplayName, Instant timestamp, IntSupplier randomSuffixSource) {
    Objects.requireNonNull(vaultDisplayName, "vaultDisplayName");
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(randomSuffixSource, "randomSuffixSource");

    String base =
        vaultDisplayName.endsWith(".vltb")
            ? vaultDisplayName.substring(0, vaultDisplayName.length() - ".vltb".length())
            : vaultDisplayName;
    base = PRIOR_COMPACTION_SUFFIX.matcher(base).replaceFirst("");
    if (base.isBlank()) {
      throw new IllegalArgumentException("Vault display name must contain a base name");
    }

    int suffix = randomSuffixSource.getAsInt();
    if (suffix < 0 || suffix > 0x00ff_ffff) {
      throw new IllegalArgumentException("Random suffix must fit in six hexadecimal characters");
    }
    return "%s-%s-%06x.vltb".formatted(base, TIMESTAMP.format(timestamp), suffix);
  }
}
