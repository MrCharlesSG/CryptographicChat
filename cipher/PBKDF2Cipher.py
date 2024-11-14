from base64 import b64decode, b64encode

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2


class PBKDF2Cipher:
    def __init__(self, user_public_key, server_private_key, salt_length=16, iterations=100_000, key_length=32):
        self.server_private_key = b64decode(server_private_key)
        self.user_public_key = b64decode(user_public_key)
        self.key_length = key_length
        self.iterations = iterations
        self.salt_length = salt_length

    def __generate_salt(self):
        hmac_hash = HMAC.new(self.server_private_key, self.user_public_key, digestmod=SHA256).digest()
        return hmac_hash[:self.salt_length]

    def __derive_encryption_key(self, salt):
        derived_key = PBKDF2(salt, b'', dkLen=self.key_length, count=self.iterations, hmac_hash_module=SHA256)
        return b64encode(derived_key).decode('utf-8')
    def derive(self):
        salt = self.__generate_salt()
        return self.__derive_encryption_key(salt)


"""
server_private_key, server_public_key = RSACipher.generate_keys()
print("Server private key", server_private_key.__str__())
print("Server public key", server_public_key.__str__())
user_private_key, user_public_key = RSACipher.generate_keys()
print("User private key", user_private_key.__str__())
print("User public key", user_public_key.__str__())
# Crear instancia de PBKDF2Cipher
pbkdf2_cipher = PBKDF2Cipher()

# Derivar una clave
derived_key = pbkdf2_cipher.derive(user_public_key, server_private_key)

# Imprimir la clave derivada en formato hexadecimal
print("Derived Key:", derived_key.hex())
"""
