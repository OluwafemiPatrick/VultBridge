package com.vultbridge.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Verifies strict roles, immutable IDs, secure generation, and session collision handling. */
class RecordIdentityTest {
  @Test
  void rolesUseOnlyTheThreeV1Codes() throws VaultDataException {
    assertEquals(RecordRole.COMMIT, RecordRole.fromCode(1));
    assertEquals(RecordRole.MANIFEST, RecordRole.fromCode(2));
    assertEquals(RecordRole.FILE, RecordRole.fromCode(3));
    assertThrows(VaultDataException.class, () -> RecordRole.fromCode(0));
    assertThrows(VaultDataException.class, () -> RecordRole.fromCode(4));
  }

  @Test
  void recordIdDefensivelyCopiesAndUsesValueEquality() {
    byte[] source = new byte[VaultFormat.RECORD_ID_BYTES];
    source[0] = 1;
    var id = new RecordId(source);
    source[0] = 2;
    byte[] returned = id.bytes();
    returned[0] = 3;

    assertArrayEquals(new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, id.bytes());
    assertEquals(id, new RecordId(id.bytes()));
    assertEquals(id.hashCode(), new RecordId(id.bytes()).hashCode());
    assertThrows(IllegalArgumentException.class, () -> new RecordId(new byte[15]));
  }

  @Test
  void productionGeneratorReturnsDistinctIdentifiers() {
    var generator = new RecordIdGenerator();
    assertNotEquals(generator.next(), generator.next());
  }

  @Test
  void deterministicGeneratorRetriesARepeatedIdentifier() {
    var source = new CollisionThenUniqueSource();
    var generator = new RecordIdGenerator(source);
    RecordId first = generator.next();
    RecordId second = generator.next();

    assertArrayEquals(filled(1), first.bytes());
    assertArrayEquals(filled(2), second.bytes());
    assertEquals(3, source.requests);
  }

  private static byte[] filled(int value) {
    byte[] bytes = new byte[VaultFormat.RECORD_ID_BYTES];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static final class CollisionThenUniqueSource implements RecordIdGenerator.ByteSource {
    private int requests;

    @Override
    public void nextBytes(byte[] destination) {
      requests++;
      Arrays.fill(destination, (byte) (requests < 3 ? 1 : 2));
    }
  }
}
