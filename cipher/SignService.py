from cipher.Sha256Cipher import SHA256Cipher
from cipher.RSACipher import RSACipher
class SignService:
    @staticmethod
    def sign(text_to_sign, private_key):
        hash_text = SHA256Cipher().hash_message(text_to_sign)
        return RSACipher.encrypt(hash_text, private_key)

    @staticmethod
    def is_correct_sign(text_signed, expected_text, public_key) -> bool:
        decrypted_hash = RSACipher.decrypt(text_signed, public_key)
        return SHA256Cipher().verify_hash(expected_text, decrypted_hash)



