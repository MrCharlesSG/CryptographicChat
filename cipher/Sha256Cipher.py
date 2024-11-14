from Crypto.Hash import SHA256


class SHA256Cipher:
    def __init__(self):
        pass  # No necesitamos un objeto de hash aquí, lo creamos en cada método

    def hash_message(self, message: str) -> str:
        """
        Crea un hash SHA-256 de un mensaje.
        """
        hash_object = SHA256.new()
        hash_object.update(message.encode('utf-8'))
        return hash_object.hexdigest()

    def verify_hash(self, message: str, expected_hash: str) -> bool:
        """
        Verifica si el hash de un mensaje coincide con el hash esperado.
        """
        generated_hash = self.hash_message(message)
        print("Generated SHA-256 Hash:", generated_hash)

        return generated_hash == expected_hash


"""
sha256_cipher = SHA256Cipher()

message = "Este es un mensaje secreto"

message_hash = sha256_cipher.hash_message(message)
print("Generated SHA-256 Hash:", message_hash)

is_valid = sha256_cipher.verify_hash(message, message_hash)
print("Is the hash valid?", is_valid)
"""
