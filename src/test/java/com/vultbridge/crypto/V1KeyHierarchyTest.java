package com.vultbridge.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/** Verifies deterministic v1 master-key creation, authenticated unlock, and key cleanup. */
class V1KeyHierarchyTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final String VECTOR_RESOURCE = "/com/vultbridge/vectors/v1-phase2.properties";

  @Test
  void productionCreationUsesSecureRandomnessAndUnlocks() throws AuthenticationFailedException {
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray());
        var created = V1KeyHierarchy.create(passphrase);
        var unlocked = V1KeyHierarchy.unlock(passphrase, created.wrappedMasterKey());
        var createdMaster = created.keys().copyMasterVaultKey();
        var unlockedMaster = unlocked.copyMasterVaultKey()) {
      assertArrayEquals(created.keys().vaultId(), unlocked.vaultId());
      assertArrayEquals(createdMaster.copy(), unlockedMaster.copy());
    }
  }

  @Test
  void deterministicCreationUnlocksToTheSameOwnedKeys() throws AuthenticationFailedException {
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray());
        var created = V1KeyHierarchy.create(passphrase, new CountingRandomSource());
        var unlocked = V1KeyHierarchy.unlock(passphrase, created.wrappedMasterKey());
        var createdMaster = created.keys().copyMasterVaultKey();
        var unlockedMaster = unlocked.copyMasterVaultKey();
        var createdHeader = created.keys().copyHeaderMacKey();
        var unlockedHeader = unlocked.copyHeaderMacKey()) {
      assertArrayEquals(created.keys().vaultId(), unlocked.vaultId());
      assertArrayEquals(createdMaster.copy(), unlockedMaster.copy());
      assertArrayEquals(createdHeader.copy(), unlockedHeader.copy());
    }
  }

  @Test
  void publicEnvelopeDefensivelyCopiesEveryArray() {
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray());
        var created = V1KeyHierarchy.create(passphrase, new CountingRandomSource())) {
      var envelope = created.wrappedMasterKey();
      byte[] firstVaultId = envelope.vaultId();
      byte[] firstSalt = envelope.kdfSalt();
      byte[] firstNonce = envelope.wrapNonce();
      byte[] firstWrapped = envelope.wrappedKey();
      firstVaultId[0] ^= 1;
      firstSalt[0] ^= 1;
      firstNonce[0] ^= 1;
      firstWrapped[0] ^= 1;

      assertFalse(Arrays.equals(firstVaultId, envelope.vaultId()));
      assertFalse(Arrays.equals(firstSalt, envelope.kdfSalt()));
      assertFalse(Arrays.equals(firstNonce, envelope.wrapNonce()));
      assertFalse(Arrays.equals(firstWrapped, envelope.wrappedKey()));
    }
  }

  @Test
  void wrongPassphraseAndEveryWrappedHeaderComponentFailAuthentication() {
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray());
        var wrongPassphrase =
            PassphraseEncoding.encode("incorrect horse battery staple".toCharArray());
        var created = V1KeyHierarchy.create(passphrase, new CountingRandomSource())) {
      WrappedMasterKey original = created.wrappedMasterKey();
      assertUnlockFails(wrongPassphrase, original);
      assertUnlockFails(passphrase, mutateVaultId(original));
      assertUnlockFails(passphrase, mutateSalt(original));
      assertUnlockFails(passphrase, mutateNonce(original));
      assertUnlockFails(passphrase, mutateWrappedTag(original));
      assertUnlockFails(
          passphrase,
          new WrappedMasterKey(
              original.vaultId(),
              new Argon2idParameters(65_536, 4, 1),
              original.kdfSalt(),
              original.wrapNonce(),
              original.wrappedKey()));
    }
  }

  @Test
  void closeDestroysRetainedSessionKeysAndIsIdempotent() {
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray())) {
      var created = V1KeyHierarchy.create(passphrase, new CountingRandomSource());
      assertFalse(created.keys().isDestroyed());

      created.close();
      created.close();

      assertTrue(created.keys().isDestroyed());
      assertThrows(IllegalStateException.class, created.keys()::copyMasterVaultKey);
      assertThrows(IllegalStateException.class, created.keys()::copyHeaderMacKey);
    }
  }

  @Test
  void partiallyFilledMasterKeyIsWipedWhenRandomSourceFails() {
    var failingSource = new FailingMasterKeyRandomSource();
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray())) {
      assertThrows(RuntimeException.class, () -> V1KeyHierarchy.create(passphrase, failingSource));
      assertTrue(failingSource.destinationWiped.getAsBoolean());
    }
  }

  @Test
  void partiallyFilledMasterKeyIsWipedWhenRandomSourceThrowsError() {
    var failingSource = new ErroringMasterKeyRandomSource();
    try (var passphrase = PassphraseEncoding.encode("correct horse battery staple".toCharArray())) {
      assertThrows(AssertionError.class, () -> V1KeyHierarchy.create(passphrase, failingSource));
      assertTrue(failingSource.destinationWiped.getAsBoolean());
    }
  }

  @Test
  void deterministicHierarchyCompositionMatchesIndependentVector()
      throws IOException, AuthenticationFailedException {
    Properties vector = loadVector();
    try (var passphrase = SensitiveBytes.copyOf(vectorBytes(vector, "passphraseHex"));
        var created = V1KeyHierarchy.create(passphrase, new VectorRandomSource(vector));
        var unlocked = V1KeyHierarchy.unlock(passphrase, created.wrappedMasterKey());
        var masterKey = created.keys().copyMasterVaultKey();
        var unlockedMasterKey = unlocked.copyMasterVaultKey()) {
      assertArrayEquals(vectorBytes(vector, "vaultId"), created.wrappedMasterKey().vaultId());
      assertArrayEquals(vectorBytes(vector, "kdfSalt"), created.wrappedMasterKey().kdfSalt());
      assertArrayEquals(vectorBytes(vector, "wrapNonce"), created.wrappedMasterKey().wrapNonce());
      assertArrayEquals(
          vectorBytes(vector, "wrappedMasterVaultKey"), created.wrappedMasterKey().wrappedKey());
      assertArrayEquals(vectorBytes(vector, "masterVaultKey"), masterKey.copy());
      assertArrayEquals(masterKey.copy(), unlockedMasterKey.copy());
    }
  }

  private static WrappedMasterKey mutateVaultId(WrappedMasterKey original) {
    byte[] changed = original.vaultId();
    changed[0] ^= 1;
    return copyWith(
        original, changed, original.kdfSalt(), original.wrapNonce(), original.wrappedKey());
  }

  private static WrappedMasterKey mutateSalt(WrappedMasterKey original) {
    byte[] changed = original.kdfSalt();
    changed[0] ^= 1;
    return copyWith(
        original, original.vaultId(), changed, original.wrapNonce(), original.wrappedKey());
  }

  private static WrappedMasterKey mutateNonce(WrappedMasterKey original) {
    byte[] changed = original.wrapNonce();
    changed[0] ^= 1;
    return copyWith(
        original, original.vaultId(), original.kdfSalt(), changed, original.wrappedKey());
  }

  private static WrappedMasterKey mutateWrappedTag(WrappedMasterKey original) {
    byte[] changed = original.wrappedKey();
    changed[changed.length - 1] ^= 1;
    return copyWith(
        original, original.vaultId(), original.kdfSalt(), original.wrapNonce(), changed);
  }

  private static WrappedMasterKey copyWith(
      WrappedMasterKey original, byte[] vaultId, byte[] salt, byte[] nonce, byte[] wrappedKey) {
    return new WrappedMasterKey(vaultId, original.parameters(), salt, nonce, wrappedKey);
  }

  private static void assertUnlockFails(SensitiveBytes passphrase, WrappedMasterKey envelope) {
    assertThrows(
        AuthenticationFailedException.class, () -> V1KeyHierarchy.unlock(passphrase, envelope));
  }

  private static Properties loadVector() throws IOException {
    var properties = new Properties();
    try (InputStream input = V1KeyHierarchyTest.class.getResourceAsStream(VECTOR_RESOURCE)) {
      if (input == null) {
        throw new IOException("Phase 2 vector resource is missing");
      }
      properties.load(input);
    }
    return properties;
  }

  private static byte[] vectorBytes(Properties vector, String key) {
    return HEX.parseHex(vector.getProperty(key));
  }

  /** Deterministic fixture that fills successive requests with increasing byte values. */
  private static final class CountingRandomSource implements RandomByteSource {
    private int next;

    @Override
    public void nextBytes(byte[] destination) {
      for (int index = 0; index < destination.length; index++) {
        destination[index] = (byte) next++;
      }
    }
  }

  /** Fails after partially filling the fourth request, which is the generated master key. */
  private static final class FailingMasterKeyRandomSource implements RandomByteSource {
    private int requests;
    private java.util.function.BooleanSupplier destinationWiped = () -> false;

    @Override
    public void nextBytes(byte[] destination) {
      requests++;
      if (requests == 4) {
        destinationWiped = () -> Arrays.equals(destination, new byte[destination.length]);
        Arrays.fill(destination, (byte) 0x5a);
        throw new IllegalStateException("Synthetic random-source failure");
      }
      Arrays.fill(destination, (byte) requests);
    }
  }

  /** Throws an Error after partially filling the generated master-key destination. */
  private static final class ErroringMasterKeyRandomSource implements RandomByteSource {
    private int requests;
    private java.util.function.BooleanSupplier destinationWiped = () -> false;

    @Override
    public void nextBytes(byte[] destination) {
      requests++;
      if (requests == 4) {
        destinationWiped = () -> Arrays.equals(destination, new byte[destination.length]);
        Arrays.fill(destination, (byte) 0x5a);
        throw new AssertionError("Synthetic random-source error");
      }
      Arrays.fill(destination, (byte) requests);
    }
  }

  /** Supplies the independent vector's fields in the hierarchy's request order. */
  private static final class VectorRandomSource implements RandomByteSource {
    private final byte[][] values;
    private int index;

    private VectorRandomSource(Properties vector) {
      values =
          new byte[][] {
            vectorBytes(vector, "vaultId"),
            vectorBytes(vector, "kdfSalt"),
            vectorBytes(vector, "wrapNonce"),
            vectorBytes(vector, "masterVaultKey")
          };
    }

    @Override
    public void nextBytes(byte[] destination) {
      byte[] source = values[index++];
      if (source.length != destination.length) {
        throw new AssertionError("Vector length does not match requested random bytes");
      }
      System.arraycopy(source, 0, destination, 0, source.length);
    }
  }
}
