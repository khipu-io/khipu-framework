package khipu.crypto.ecc;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

public class Test {
  public static void main(String... args) {
    try {
      test_scheme_ecc(128);
    } catch (NoSuchAlgorithmException
        | IllegalBlockSizeException
        | InvalidKeyException
        | BadPaddingException
        | InvalidAlgorithmParameterException
        | NoSuchPaddingException
        | NoSuchProviderException
        | ShortBufferException ex) {
      Logger.getLogger(Test.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

  public static void test_scheme_ecc(int nBitsOfKey)
      throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
          BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException,
          NoSuchProviderException, ShortBufferException {

    // the plainText could also be a AES key
    String plainText = "plaintext message from alice to bob";
    System.out.println("0. Original plaintext message: '" + plainText + "'");

    AESKey aliceAESKey = AES.generateKey(nBitsOfKey);

    byte[] encryptedPlainTextMessageFromAlice =
        AES.encrypt(
            plainText.getBytes(StandardCharsets.UTF_8), aliceAESKey.getKey(), aliceAESKey.getIV());
    System.out.println(
        "1. Alice encrypted message: " + convertBytesToHex(encryptedPlainTextMessageFromAlice));

    // Necessary Key + IV information to reconstruct the key
    byte[] keyInformation =
        ByteBuffer.allocate(aliceAESKey.getKey().getEncoded().length + aliceAESKey.getIV().length)
            .put(aliceAESKey.getKey().getEncoded())
            .put(aliceAESKey.getIV())
            .array();
    System.out.println(
        "2. Alice's Key || IV used to encrypt plain message: "
            + convertBytesToHex(keyInformation)
            + ", "
            + keyInformation.length
            + " bytes");

    // Initialize two key pairs
    KeyPair aliceECKeyPair = ECC.generateKeyPair();
    KeyPair bobECKeyPair = ECC.generateKeyPair();

    System.out.println(
        "3. Alice EC public key in DER form: "
            + convertBytesToHex(aliceECKeyPair.getPublic().getEncoded())
            + ", "
            + aliceECKeyPair.getPublic().getEncoded().length
            + " bytes, format "
            + aliceECKeyPair.getPublic().getFormat());

    byte[] subjectPublicKeyBytes = ECC.getECPointBytesFromECPublicKey(aliceECKeyPair.getPublic());
    System.out.println(
        "3a Alice EC public key in ECPoint: "
            + convertBytesToHex(subjectPublicKeyBytes)
            + ", "
            + subjectPublicKeyBytes.length
            + " bytes");

    System.out.println(
        "4. Alice EC private key: "
            + convertBytesToHex(aliceECKeyPair.getPrivate().getEncoded())
            + ", "
            + aliceECKeyPair.getPrivate().getEncoded().length
            + " bytes, format "
            + aliceECKeyPair.getPrivate().getFormat());

    // Create two AES secret keys to encrypt/decrypt the message
    SecretKey aliceSharedSecret =
        ECC.generateSharedSecret(aliceECKeyPair.getPrivate(), bobECKeyPair.getPublic());
    System.out.println(
        "5. Alice Shared Secret Key: "
            + convertBytesToHex(aliceSharedSecret.getEncoded())
            + ", "
            + aliceSharedSecret.getEncoded().length
            + " bytes");

    // Encrypt the message using 'aliceSharedSecret'
    final byte[] eccIV = ECC.randomIV(); // should be kept somewhere to decrypt later

    byte[] encryptedKeyForBob = ECC.encrypt(aliceSharedSecret, keyInformation, eccIV);
    System.out.println(
        "6. Encrypted key for Bob: "
            + convertBytesToHex(encryptedKeyForBob)
            + ", "
            + encryptedKeyForBob.length
            + " bytes");

    // Decrypt the message using 'bobSharedSecret'
    SecretKey bobSharedSecret =
        ECC.generateSharedSecret(bobECKeyPair.getPrivate(), aliceECKeyPair.getPublic());
    System.out.println(
        "7. Bob Shared Secret Key: "
            + convertBytesToHex(bobSharedSecret.getEncoded())
            + ", should be same as 5.");

    byte[] decryptedKeyFromAlice = ECC.decrypt(bobSharedSecret, encryptedKeyForBob, eccIV);
    System.out.println(
        "8. Decrypted Key || IV to decrypt Alice plain message: "
            + convertBytesToHex(decryptedKeyFromAlice)
            + ", should be same as 2.");

    AESKey reconstructedKey = new AESKey(decryptedKeyFromAlice);

    byte[] decryptedText =
        AES.decrypt(
            encryptedPlainTextMessageFromAlice,
            reconstructedKey.getKey(),
            reconstructedKey.getIV());
    System.out.println(
        "9. Decrypted plain text message: '"
            + new String(decryptedText, StandardCharsets.UTF_8)
            + "', should be same as 0.");
  }

  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

  public static String convertBytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars).toLowerCase();
  }
}
