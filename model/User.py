import json
import os
from base64 import b64encode
from datetime import datetime

from cipher.PBKDF2Cipher import PBKDF2Cipher
from cipher.RSACipher import RSACipher
from cipher.AESCipher import AESCipher


class User:
    def __init__(self, username, pbk, prk, enc_key, decrypted_server_enc_key):
        self.id = str(os.urandom(8).hex())
        self.username = username
        self.public_key = pbk
        self.private_key = prk
        self.decrypted_server_enc_key = decrypted_server_enc_key
        self.server_enc_key = enc_key

    def get_decrypted_server_enc_key(self, server_private_key= None):
        if self.decrypted_server_enc_key is None:
            if server_private_key is not None:
                self.decrypted_server_enc_key = RSACipher.decrypt(self.server_enc_key, server_private_key)
            else:
                raise Exception("Need the priovate key")
        return self.decrypted_server_enc_key

    def get_info(self):
        return f"{self.username}|{self.public_key}"

    @staticmethod
    def get_from_info(data_string):
        parts = data_string.split("|")

        if len(parts) != 2:
            raise ValueError("Formato de cadena no válido para crear un mensaje")

        username, public_key = parts
        return username, public_key

    @staticmethod
    def create_user(username, password, server_public_key):
        prk, pbk = RSACipher.generate_keys()
        prk_encrypted = AESCipher(password).encrypt(prk)  # add PEPPER
        enc_key = AESCipher.generateKey()
        enc_key_encrypted = RSACipher.encrypt(enc_key, server_public_key)
        return User(username, pbk, prk_encrypted, enc_key_encrypted, enc_key)

    def decrypt_prk(self, password):
        return AESCipher(password).decrypt(self.private_key)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "public_key": self.public_key,
            "private_key": self.private_key,
            "server_enc_key": self.server_enc_key,
            "decrypted_server_enc_key": self.decrypted_server_enc_key
        }

    @staticmethod
    def from_dict(data):
        user = User.__new__(User)
        user.id = data["id"]
        user.username = data["username"]
        user.public_key = data["public_key"]
        user.private_key = data["private_key"]
        user.server_enc_key = data["server_enc_key"]
        user.decrypted_server_enc_key = data["decrypted_server_enc_key"]
        return user
