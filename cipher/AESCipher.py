import pickle
from base64 import b64decode, b64encode
from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    @staticmethod
    def generateKey():
        return b64encode(get_random_bytes(16)).decode('utf-8')

    def encrypt(self, data):
        """
        Cifra un objeto Message
        """
        message_bytes = pickle.dumps(data)

        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        encrypted_message = iv + cipher.encrypt(pad(message_bytes, AES.block_size))
        return b64encode(encrypted_message).decode('utf-8')

    def decrypt(self, data_encrypted):
        """
        Descifra un mensaje cifrado y regresa el objeto Message original
        """
        raw = b64decode(data_encrypted)

        iv = raw[:AES.block_size]
        encrypted_data = raw[AES.block_size:]

        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        return pickle.loads(decrypted_data)


"""
key = AESCipher.generateKey()
print("Private key", key.hex())

aes_cipher = AESCipher(key)

message = Message("Este es un mensaje secreto", "Juan", 1, "signature")

ciphertext = aes_cipher.encrypt(message)
print("Ciphertext:", ciphertext)

decrypted_message = aes_cipher.decrypt(ciphertext)
print("Decrypted message:", decrypted_message.get_string())


key = AESCipher.generateKey()
print("Private key", key.hex())

aes_cipher = AESCipher(key)

message = Message("Este es un mensaje secreto", "Juan", 1, "signature")

ciphertext = aes_cipher.encrypt(StringForSymmetricEncryption("Este es un mensaje secreto"))
print("Ciphertext:", ciphertext)

decrypted_message = aes_cipher.decrypt(ciphertext)
print("Decrypted message:", decrypted_message.get_string())
"""
