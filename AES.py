import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(plaintext, key):
  if len(key) not in (16, 24, 32):
    raise ValueError("key must be 16, 24, or 32 bytes long")
  cipher = AES.new(key, AES.MODE_GCM)
  ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
  return ciphertext, tag


def decrypt(ciphertext, key, tag):
  if len(key) not in (16, 24, 32):
    raise ValueError("key must be 16, 24 or 32 bytes long")
  cipher = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)
  try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')
  except ValueError:
    return None


def generate_key(key_size=256):
  if key_size not in (128, 192, 256):
    raise ValueError("key size must be 128, 192 or 256")
  return get_random_bytes(key_size // 8)


if __name__ == "__main__":
  key = generateKey()
  plaintext = "this is a secret message"
  ciphertext, tag = encrypt(plaintext, key)
  decrypted_text = decrypt(ciphertext, key, tag)

  if decrypted_text:
    print("decrypted text:", decrypted_text)
  else:
    print("decryption failed (invalid tag)")

  tampered_ciphertext = ciphertext[:-1] + b'\0'
  tampered_decrypted_text = decrypt(tampered_ciphertext, key, tag)
  if tampered_decrypted_text:
    print("tampered decrypted text:", tampered_decrypted_text)
  else:
    print("tampered decryption failed (invalid tag)")

