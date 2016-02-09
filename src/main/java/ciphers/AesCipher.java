package ciphers;

import com.google.common.io.BaseEncoding;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author guymarom
 */
public class AesCipher {

  public final static String CHARSET_ENCODING = "UTF-8";
  public final int SALT_LENGTH = 16;
  private SecretKeyFactory keyFactory;
  public final String ALGORITHM = "AES";
  private final char[] PASSWORD = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
  private final int ITERATIONS = 20000;
  private final int KEY_LENGTH = 256;
  private Cipher encryptingCipher;
  private Cipher decryptingCipher;

  public AesCipher() {
    try {
      keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Failure!!!", e);
    }

    initEncryptingCipher();
    initDecryptingCipher();
  }

  private void initEncryptingCipher() {
    try {
      encryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    }
  }

  private void initDecryptingCipher() {
    try {
      decryptingCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    }
  }

  public static void main(final String[] args) throws Exception {
    AesCipher aesCipher = new AesCipher();

    final String message = "blah";
    String encrypted = aesCipher.encrypt(message);
    System.out.println(aesCipher.decrypt(encrypted));
  }

  public String encrypt(String message) throws Exception {
    SecureRandom secureRandom = initSecureRandom();
    byte[] salt = generateSalt(secureRandom);
    final Key key = createKey(salt);

    encryptingCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(salt));
    byte[] encrypted = encryptingCipher.doFinal(message.getBytes(CHARSET_ENCODING));
    final byte[] data = ArrayUtils.addAll(salt, encrypted);
    return BaseEncoding.base64().encode(data);
  }

  public String decrypt(final String encrypted) throws Exception {
    initSecureRandom();
    final byte[] data = BaseEncoding.base64().decode(encrypted);
    final byte[] salt = Arrays.copyOf(data, SALT_LENGTH);
    final Key key = createKey(salt);

    decryptingCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(salt));

    final byte[] message = Arrays.copyOfRange(data, SALT_LENGTH, data.length);
    byte[] decypted = decryptingCipher.doFinal(message);
    return new String(decypted, CHARSET_ENCODING);
  }

  private byte[] generateSalt(final SecureRandom secureRandom) {
    byte[] salt = new byte[SALT_LENGTH];
    secureRandom.nextBytes(salt);
    return salt;
  }

  private Key createKey(final byte[] salt) throws Exception {
    final PBEKeySpec spec = new PBEKeySpec(PASSWORD, salt, ITERATIONS, KEY_LENGTH);
    final SecretKey secretKey = keyFactory.generateSecret(spec);
    SecretKeySpec result = new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);
    spec.clearPassword();
    return result;
  }

  private SecureRandom initSecureRandom() {
    try {
      return SecureRandom.getInstance("SHA1PRNG", "SUN");
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException("Error creating SecureRandom", e);
    } catch (final NoSuchProviderException e) {
      throw new RuntimeException("Error creating SecureRandom", e);
    }
  }
}
