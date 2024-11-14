from base64 import b64encode, b64decode

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class RSACipher:

    @staticmethod
    def generate_keys(
            bits=3072):  # according to nist https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
        """
        Genera un par de claves RSA (pública y privada)
        """
        key = RSA.generate(bits)
        private_key = b64encode(key.export_key()).decode('utf-8')
        public_key = b64encode(key.publickey().export_key()).decode('utf-8')
        return private_key, public_key

    @staticmethod
    def encrypt(data, key):
        """
        Cifra los datos usando la clave pública
        """
        # Convertir los datos a bytes si no lo son
        if isinstance(data, str):
            data = data.encode()

        key = b64decode(key)

        cipher = PKCS1_OAEP.new(RSA.import_key(key))
        ciphertext = cipher.encrypt(data)
        return b64encode(ciphertext).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext, key):
        """
        Descifra los datos usando la clave privada
        """
        key = b64decode(key)
        raw = b64decode(ciphertext)
        cipher = PKCS1_OAEP.new(RSA.import_key(key))
        plaintext = cipher.decrypt(raw)
        return plaintext.decode()


"""
private_key, public_key = RSACipher.generate_keys()
print(private_key)
print(public_key)
# Crear una instancia de RSACipher
private_key, public_key = RSACipher.generate_keys()
print("Private key", private_key.__str__())
print("Public key", public_key.__str__())
rsa_cipher = RSACipher(private_key, public_key)

# Cifrar un mensaje
message = "Este es un mensaje secreto"
ciphertext = rsa_cipher.encrypt(message)
print("Ciphertext:", ciphertext)

# Descifrar el mensaje
decrypted_message = rsa_cipher.decrypt(ciphertext)
print("Decrypted message:", decrypted_message)
"""
