package khipu.crypto.ecc;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {
  // For both CBC mode and CFB mode, the initialization vector is the size of a
  // block, which for AES is 16 bytes = 128 bits
  public static int IV_LENGTH = 16;

  private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";

  /**
   * @param nBitsOfKey, length in bits 128, 192, 256 etc
   * @return AESKey
   * @throws NoSuchAlgorithmException
   */
  public static AESKey generateKey(int nBitsOfKey) throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(nBitsOfKey);

    SecretKey key = keyGenerator.generateKey();
    byte[] IV = new byte[IV_LENGTH];
    SecureRandom random = new SecureRandom();
    random.nextBytes(IV);

    return new AESKey(key, IV);
  }

  public static byte[] encrypt(byte[] plainText, SecretKey key, byte[] IV)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

    Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
    SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
    IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
    byte[] cipherText = cipher.doFinal(plainText);
    return cipherText;
  }

  public static byte[] decrypt(byte[] cipherText, SecretKey key, byte[] IV)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
          InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

    Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
    SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(IV);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    byte[] decryptedText = cipher.doFinal(cipherText);
    return decryptedText;
  }

  public static byte[] serializeSecretKey(SecretKey key) {
    return key.getEncoded();
  }

  public static SecretKey deserializeSecretKey(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
  }
}
