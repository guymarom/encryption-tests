package ciphers;

import com.google.common.io.BaseEncoding;
import org.apache.commons.lang3.ArrayUtils;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public class AESEncryptor implements StringEncryptor {

  private static final int SALT_LENGTH = 16;
  private static final String ALGORITHM = "AES";
  private static final int ITERATIONS = 20000;
  private static final int KEY_LENGTH = 256;

  private final String password;
  private final SecretKeyFactory keyFactory;

  private volatile SecureRandom secureRandom;
  private volatile long lastInitTime;

  public AESEncryptor(final String password) {
    this.password = password;

    try {
      keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException("Error generating SecretKeyFactory", e);
    }
  }

  public String encrypt(final String message) {
    final byte[] salt = generateSalt();
    final Key key = createKey(salt);

    final Cipher encryptingCipher = createCipher(Cipher.ENCRYPT_MODE, key, salt);
    final byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
    final byte[] encryptedBytes = doFinal(encryptingCipher, messageBytes);
    final byte[] data = ArrayUtils.addAll(salt, encryptedBytes);
    return BaseEncoding.base64().encode(data);
  }

  public String decrypt(final String encryptedMessage) {
    final byte[] data = BaseEncoding.base64().decode(encryptedMessage);

    final byte[] salt = Arrays.copyOf(data, SALT_LENGTH);
    if (salt == null || salt.length != SALT_LENGTH)
      throw new EncryptionOperationNotPossibleException("Could not decrypt message, probably incorrect encryption");

    final Key key = createKey(salt);
    final Cipher decryptingCipher = createCipher(Cipher.DECRYPT_MODE, key, salt);

    final byte[] encryptedBytes = Arrays.copyOfRange(data, SALT_LENGTH, data.length);
    if (encryptedBytes == null || encryptedBytes.length == 0)
      throw new EncryptionOperationNotPossibleException("Could not decrypt message, probably incorrect encryption");

    final byte[] messageBytes = doFinal(decryptingCipher, encryptedBytes);
    return new String(messageBytes, StandardCharsets.UTF_8);
  }

  private byte[] doFinal(final Cipher cipher, final byte[] bytes) {
    try {
      return cipher.doFinal(bytes);
    } catch (final IllegalBlockSizeException e) {
      throw new EncryptionOperationNotPossibleException(e);
    } catch (final BadPaddingException e) {
      throw new EncryptionOperationNotPossibleException(e);
    }
  }

  private Cipher createCipher(final int mode, final Key key, final byte[] salt) {
    try {
      final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(mode, key, new IvParameterSpec(salt));
      return cipher;
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException("Could not create cipher", e);
    } catch (final NoSuchPaddingException e) {
      throw new RuntimeException("Could not create cipher", e);
    } catch (final InvalidAlgorithmParameterException e) {
      throw new RuntimeException("Could not create cipher", e);
    } catch (final InvalidKeyException e) {
      throw new RuntimeException("Could not create cipher", e);
    }
  }

  private void initSecureRandom() {
    try {
      secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
      lastInitTime = System.currentTimeMillis();
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException("Error creating SecureRandom", e);
    } catch (final NoSuchProviderException e) {
      throw new RuntimeException("Error creating SecureRandom", e);
    }
  }

  private byte[] generateSalt() {
    final SecureRandom secureRandom = getSecureRandom();
    final byte[] salt = new byte[SALT_LENGTH];
    secureRandom.nextBytes(salt);
    return salt;
  }

  private SecureRandom getSecureRandom() {
    if (shouldReinitSecureRandom()) {
      initSecureRandom();
    }
    return secureRandom;
  }

  //Reinit secureRandom every hour to prevent too many values to be created with the same seed
  private boolean shouldReinitSecureRandom() {
    final long timeSinceLastInit = System.currentTimeMillis() - lastInitTime;
    return TimeUnit.MILLISECONDS.toHours(timeSinceLastInit) > 1;
  }

  private Key createKey(final byte[] salt) {
    final PBEKeySpec spec = new PBEKeySpec(password.toCharArray(),
                                           salt,
                                           ITERATIONS,
                                           KEY_LENGTH);
    final SecretKey secretKey;
    try {
      secretKey = keyFactory.generateSecret(spec);
    } catch (final InvalidKeySpecException e) {
      throw new RuntimeException("Error creating SecretKey", e);
    }
    final SecretKeySpec result = new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);
    spec.clearPassword();
    return result;
  }

  public static void main(final String[] args) {
    AESEncryptor enc = new AESEncryptor("password");
    System.out.println(enc.decrypt(enc.encrypt("testing")));
  }
}
