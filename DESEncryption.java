import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import java.util.Base64;

public class DESEncryption {
  public static String encrypt(String plaintext, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] ciphertextBytes = cipher.doFinal(plaintext.getBytes());
    return Base64.getEncoder().encodeToString(ciphertextBytes);
  }
  public static String decrypt(String ciphertext, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
    byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);
    return new String(plaintextBytes);
  }
  public static SecretKey generateKey() throws Exception {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
    keyGenerator.init(56);
    return keyGenerator.generateKey();
  }
  public static void main(String[] args) throws Exception {
    SecretKey key = generateKey();
    String plaintext = "this is a DES message";
    String ciphertext = encrypt(plaintext, key);
    System.out.println("ciphertext: " + ciphertext);

    String decryptedText = decrypt(ciphertext, key);
    System.out.println("decrypted text: " + decryptedText);

    System.out.println("are they equal?" + plaintext.equals(decryptedText));
  }
}
