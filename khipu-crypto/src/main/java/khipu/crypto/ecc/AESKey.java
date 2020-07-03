package khipu.crypto.ecc;

import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESKey {
  private SecretKey key;
  private byte[] IV; // Initialization Vector

  public AESKey(final SecretKey key, final byte[] IV) {
    this.key = key;
    this.IV = IV;
  }

  // This takes in SK || IV for AES256 and creates the SecretKey object and
  // corresponding IV byte array.
  public AESKey(final byte[] skConcatIVBytes) {
    int total_bytes = skConcatIVBytes.length;
    // the IV is always 16 bytes, key is 32 bytes for AES256. 16 bytes for AES128
    int nBytesOfKey = skConcatIVBytes.length - AES.IV_LENGTH;
    byte[] sk = Arrays.copyOfRange(skConcatIVBytes, 0, nBytesOfKey);
    byte[] iv = Arrays.copyOfRange(skConcatIVBytes, nBytesOfKey, total_bytes);

    key = new SecretKeySpec(sk, 0, sk.length, "AES");
    IV = iv;
  }

  public void setIV(byte[] IV) {
    this.IV = IV;
  }

  public void setKey(SecretKey key) {
    this.key = key;
  }

  public byte[] getIV() {
    return IV;
  }

  public SecretKey getKey() {
    return key;
  }
}
