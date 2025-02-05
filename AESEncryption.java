import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESEncrytpion {
  private static final String AES_ALGORITHM = "AES";

  public static String encrypt(String plaintext, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] ciphertextBytes = cipher.doFinal(plaintext, getBytes());
    return Base.64.getEncoder().encodeToString(ciphertextBytes);
  }
  public static String decrypt(String ciphertext, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
    byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);
    return new String(plaintextBytes);
  }
  public static SecretKey generateKey() throws Exception {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
    keyGenerator.init(256);
    return keyGenerator.generateKey();
  }
  public static SecretKey loadKey(String encodedKey) {
    byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
    return new SecretKeySpec(decodedKey, 0, decodedKey.length, AES_ALGORITHM);
  }
  public static String encodeKey(SecretKey key) {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }
  public static void main(String[] args) throws Exception {
    SecretKey key = generateKey();
    String encodedKey = encodeKey(key);
    System.out.println("encoded key (store securely):" + encodedKey);

    String plaintext = "this is a secret message";
    String ciphertext = encrypt(plaintext, key);
    System.out.println("ciphertext: " + ciphertext);
    String decryptedText = decrypt(ciphertext, key);
    System.out.println("decrypted text: " + decryptedText);
    // verify
    System.out.println("are they equal?" + plaintext.equals(decryptedText));
  }
  
