package ciphers;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.StringPBEConfig;
import org.jasypt.salt.RandomSaltGenerator;

public class JasyptCipher {

  private static final String PASSWORD = "passowrd";
  private static final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();

  public static void main(final String[] args) {
    encryptor.setPassword(PASSWORD);
    encryptor.setAlgorithm("AES/CBC/PKCS5Padding");
    encryptor.setKeyObtentionIterations(20000);
    encryptor.setSaltGenerator(new RandomSaltGenerator());
//    encryptor.setAlgorithm("PBKDF2WithHmacSHA1");
    System.out.println(decrypt(encrypt("testing")));
  }

  public static String encrypt(String value) {
    return encryptor.encrypt(value);
  }

  public static String decrypt(String data) {
    return encryptor.decrypt(data);
  }

}
