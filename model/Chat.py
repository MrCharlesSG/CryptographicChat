import json
import os
from base64 import b64encode
from datetime import datetime

from cipher.PBKDF2Cipher import PBKDF2Cipher
from cipher.RSACipher import RSACipher
from cipher.AESCipher import AESCipher
from model.User import User


class Chat:
    def __init__(self, user_1: User = None, user_2: User = None, server_private_key=None):
        self.chat_id = str(os.urandom(8).hex())
        if user_1 is not None and user_2 is not None and server_private_key is not None:
            self.user1_pbk_for_server = PBKDF2Cipher(user_1.get_decrypted_server_enc_key(server_private_key),
                                                     server_private_key).derive()
            self.user2_pbk_for_server = PBKDF2Cipher(user_2.get_decrypted_server_enc_key(server_private_key),
                                                     server_private_key).derive()
            enc_key = AESCipher.generateKey()
            print("the key in chat of ", user_1.username, " is ", enc_key)
            self.enc_key_user1 = AESCipher(user_1.get_decrypted_server_enc_key()).encrypt(enc_key)
            self.enc_key_user2 = AESCipher(user_2.get_decrypted_server_enc_key()).encrypt(enc_key)
            aes = AESCipher(enc_key)
            self.participant_info_user1 = aes.encrypt(user_1.get_info())
            self.participant_info_user2 = aes.encrypt(user_2.get_info())
            self.enc_key_real = enc_key

    @staticmethod
    def create_chat(user1_pbk_for_server, user2_pbk_for_server, user_1: User, user_2: User):
        chat = Chat()
        chat.user1_pbk_for_server = user1_pbk_for_server
        chat.user2_pbk_for_server = user2_pbk_for_server
        enc_key = AESCipher.generateKey()
        print("the key in chat of ", user_1.username, " is ", enc_key)
        chat.enc_key_user1 = AESCipher(user_1.get_decrypted_server_enc_key()).encrypt(enc_key)
        chat.enc_key_user2 = AESCipher(user_2.get_decrypted_server_enc_key()).encrypt(enc_key)
        aes = AESCipher(enc_key)
        chat.participant_info_user1 = aes.encrypt(user_1.get_info())
        chat.participant_info_user2 = aes.encrypt(user_2.get_info())
        chat.enc_key_real = enc_key
        return chat

    def get_chat_str(self, user: User, is_first=True):
        enc_key = ""
        if (is_first):
            enc_key = AESCipher(user.decrypted_server_enc_key).decrypt(self.enc_key_user1)
        else:
            enc_key = AESCipher(user.decrypted_server_enc_key).decrypt(self.enc_key_user2)

        print("The key decrypted ", enc_key)
        aes = AESCipher(enc_key)
        part_1 = aes.decrypt(self.participant_info_user1)
        print("The par1 ", part_1)
        part_2 = aes.decrypt(self.participant_info_user2)
        print("The par2 ", part_2)
        return f"{part_2}|{part_1}|"

    def to_dict(self):
        return {
            "chat_id": self.chat_id,
            "enc_key_user1": self.enc_key_user1,
            "enc_key_user2": self.enc_key_user2,
            "participant_info_user1": self.participant_info_user1,
            "participant_info_user2": self.participant_info_user2,
            "enc_key_real": self.enc_key_real,
            "user1_pbk_for_server": self.user1_pbk_for_server,
            "user2_pbk_for_server": self.user2_pbk_for_server,
        }

    @staticmethod
    def from_dict(data):
        chat = Chat.__new__(Chat)
        chat.chat_id = data["chat_id"]
        chat.enc_key_user1 = data["enc_key_user1"]
        chat.enc_key_user2 = data["enc_key_user2"]
        chat.participant_info_user1 = data["participant_info_user1"]
        chat.participant_info_user2 = data["participant_info_user2"]
        chat.enc_key_real = data["enc_key_real"]
        chat.user1_pbk_for_server = data["user1_pbk_for_server"]
        chat.user2_pbk_for_server = data["user2_pbk_for_server"]
        return chat
