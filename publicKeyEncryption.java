import java.security.*;
import javax.crypto.*;
import java.util.*;

public class PublicKeyDemo1 {
  private static KeyPair keyPair;
  private staic String algorithm = "RSA";
  public static void main(String[] args) trhows Exception {
    KeypairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    keyPairGenerator.initialize(1024);
    keyPair = keyPairGenerator.generateKeyPair();
    final Cipher cipher = Cipher.getInstance(algorithm);
    final String plaintext = "hello world";
    System.out.println("public key = " + keyPair.getPublic().toString());
    System.out.println("private key = " + keyPair.getPrivate().toString());
    // ENCRYPT using pulbic key
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
    String ciphertext = new String(Base64.getEncoder().encode(encryptedBytes));
    System.out.println("encrypted (ciphertext) = " + ciphertext);
    // decrypt using private key
    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext.getBytes());
    byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);
    String decryptedString = new String(decryptedBytes);
    System.out.println("decrypted (plaintext) = " + decryptedString);
  }
}
