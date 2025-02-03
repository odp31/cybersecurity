// EX 9.1: PRIVATE KEY ENCRYPTION

import java.security.*;
import javax.crypto.*;

public class PrivateKeyDemo1 {
  static String algorithm = "AES";
  static Key key; 
  static Cipher cipher;
  public static void main(String[] args) throws Exception {
    key = KeyGenerator.getInstance(algorithm).generateKey();
    cipher = Cipher.getInstance(algorithm);
    String text = "Hello World";
    byte[] encryptionBytes = encrypt(text);
    System.out.println("Original text: " + text);
    System.out.println("key: " + key.toString());
    System.out.println("Encrypted Text: " + encrypt(text));
    System.out.println("Decrypted Text: " + decrypt(encryptionBytes));
  }
  private static byte encrypt(String input) throws Exception {
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] inputBytes = input.getBytes();
    return cipher.doFinal(inputBytes);
  }
  private static String decrypt(byte[] encryptionBytes) throws Exception {
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] recoveredBytes = cipher.doFinal(encryptionBytes);
    String recovered = new String(recoveredBytes);
    return recovered;
  }
}
