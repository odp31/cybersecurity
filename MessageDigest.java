import java.security.MessageDigest;
public class MessageDigestDemo1 {
  public static void main(String[] args) trhows Exception {
    String stringToEncrypt = "Hello World";
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(stringToEncrypt.getBytes());
    String encryptedString = new String(messageDigest.digest());
    System.out.println("Original Text: " + stringToEncrypt);
    System.out.println("Message Digest; " + encryptedString);
  }
}


public class MessageDigestDemo2 {
  public static void main(String[] args) trhows Exception {
    String stringToEncrypt = "Hello World";
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    byte[] encodedhash = messageDigest.digest(stringToEncrypt.getBytes());
    String encryptedString = bytesToHex(encodedhash);
    System.out.println("original text: " + stringToEncrypt);
    System.out.println("message digest: " + encryptedString);
  }
  private static String bytesToHex(byte[] hash) {
    StringBuffer hexString = new StringBuffer();
    for(int i = 0; i < hash.length; i++) {
      String hex = Integer.toHexString(0xff & hash[i]);
      if(hex.length() == 1) hexString.append('0');
      hexString.append(hex);
    }
    return hexString.toString();
  }
}
