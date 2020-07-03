package khipu.crypto.ecc;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class ECC {
  private static final String BC = BouncyCastleProvider.PROVIDER_NAME; // "BC"
  private static final String ECDH = "ECDH";
  private static final String SECP256R1 = "secp256r1";
  private static final KeyPairGenerator KEY_PAIR_GENERATOR;

  private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";

  static {
    Security.addProvider(new BouncyCastleProvider());

    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(SECP256R1);
    try {
      KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance(ECDH, BC);
      KEY_PAIR_GENERATOR.initialize(parameterSpec);
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | InvalidAlgorithmParameterException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static byte[] randomIV() {
    return new SecureRandom().generateSeed(AES.IV_LENGTH);
  }

  public static KeyPair generateKeyPair()
      throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {

    return KEY_PAIR_GENERATOR.generateKeyPair();
  }

  public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey)
      throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {

    KeyAgreement keyAgreement = KeyAgreement.getInstance(ECDH, BC);
    keyAgreement.init(privateKey);
    keyAgreement.doPhase(publicKey, true);

    return keyAgreement.generateSecret("AES");
  }

  public static byte[] encrypt(SecretKey key, byte[] plainTextBytes, byte[] iv)
      throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException,
          BadPaddingException, IllegalBlockSizeException {

    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, BC);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    byte[] encryptedBytes = new byte[cipher.getOutputSize(plainTextBytes.length)];
    int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, encryptedBytes, 0);
    cipher.doFinal(encryptedBytes, encryptLength);

    return encryptedBytes;
  }

  public static byte[] decrypt(SecretKey key, byte[] encryptedBytes, byte[] iv)
      throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException,
          BadPaddingException, IllegalBlockSizeException {

    Key decryptionKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, BC);
    cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);

    byte[] plainTextBytes = new byte[cipher.getOutputSize(encryptedBytes.length)];
    int decryptLength = cipher.update(encryptedBytes, 0, encryptedBytes.length, plainTextBytes, 0);
    cipher.doFinal(plainTextBytes, decryptLength);

    return plainTextBytes;
  }

  public static PrivateKey getPrivateKeyFromBytes(byte[] encodedKey)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

    // A KeyFactory is used to convert encoded keys to their actual Java instance
    KeyFactory ecKeyFac = KeyFactory.getInstance(ECDH, BC);

    // now take the encoded value and recreate the private key
    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
    PrivateKey privateKey = ecKeyFac.generatePrivate(pkcs8EncodedKeySpec);
    return privateKey;
  }

  public static PublicKey getPublicKeyFromBytes(byte[] encodedKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

    // A KeyFactory is used to convert encoded keys to their actual Java instance
    KeyFactory ecKeyFac = KeyFactory.getInstance(ECDH, BC);

    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
    PublicKey publicKey = ecKeyFac.generatePublic(x509EncodedKeySpec);
    return publicKey;
  }

  /*-
    System.out.println(ASN1Dump.dumpAsString(pubKeySequence))
    DER Sequence
       DER Sequence
         ObjectIdentifier(1.2.840.10045.2.1)
         ObjectIdentifier(1.2.840.10045.3.1.7) DER Bit String[65, 0]

    https://tools.ietf.org/html/rfc5480

    2.1.  Elliptic Curve Cryptography Public Key Algorithm Identifiers

      id-ecPublicKey OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }

      secp256r1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 }

    2.2. Subject Public Key

    The subjectPublicKey from SubjectPublicKeyInfo is the ECC public key. ECC public keys have
    the following syntax:

      ECPoint ::= OCTET STRING

    Implementations of Elliptic Curve Cryptography according to this document MUST support the
    uncompressed form and MAY support the compressed form of the ECC public key. The hybrid form of
    the ECC public key from [X9.62] MUST NOT be used. As specified in [SEC1]:

      o The elliptic curve public key (a value of type ECPoint that is an OCTET STRING) is mapped
        to a subjectPublicKey (a value of type BIT STRING) as follows: the most significant bit of the
        OCTET STRING value becomes the most significant bit of the BIT STRING value, and so on; the
        least significant bit of the OCTET STRING becomes the least significant bit of the BIT STRING.
        Conversion routines are found in Sections 2.3.1 and 2.3.2 of [SEC1].

      o The first octet of the OCTET STRING indicates whether the key is compressed or
        uncompressed. The uncompressed form is indicated by 0x04 and the compressed form is indicated
        by either 0x02 or 0x03 (see 2.3.3 in [SEC1]). The public key MUST be rejected if any other
        value is included in the first octet.
  */
  private static final ASN1ObjectIdentifier ID_ECPUBLICKEY =
      new ASN1ObjectIdentifier("1.2.840.10045.2.1");
  private static final ASN1ObjectIdentifier ID_SECP256R1 =
      new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");
  private static final DERSequence ALGORITHM_ID =
      new DERSequence(new ASN1Encodable[] {ID_ECPUBLICKEY, ID_SECP256R1});

  /**
   * @param ecPointBytes 32 bytes * 2
   * @return EC public key
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws NoSuchProviderException
   * @throws IOException
   */
  public static PublicKey getECPublicKeyFromBytes(byte[] ecPointBytes)
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
          IOException {

    byte[] uncompressed = new byte[ecPointBytes.length + 1];
    uncompressed[0] = 0x04; // uncompressed prefix byte is 0x04
    System.arraycopy(ecPointBytes, 0, uncompressed, 1, ecPointBytes.length);

    DERBitString ecPoint = new DERBitString(uncompressed, 0);
    DERSequence pubKeySequence = new DERSequence(new ASN1Encodable[] {ALGORITHM_ID, ecPoint});
    byte[] encodedKey = pubKeySequence.getEncoded();

    return getPublicKeyFromBytes(encodedKey);
  }

  /**
   * @param pubKey
   * @return ECPoint X, Y in bytes, 32 bytes * 2
   */
  public static byte[] getECPointBytesFromECPublicKey(PublicKey pubKey) {
    ASN1Sequence pubKeySequence = DERSequence.getInstance(pubKey.getEncoded());
    DERBitString subjectPublicKey = (DERBitString) pubKeySequence.getObjectAt(1);

    byte[] uncompressed = subjectPublicKey.getBytes();
    byte[] ecpoint = new byte[uncompressed.length - 1]; // strip prefix 0x04
    System.arraycopy(uncompressed, 1, ecpoint, 0, ecpoint.length);

    return ecpoint;
  }
}
