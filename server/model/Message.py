import os
from datetime import datetime

from cipher.AESCipher import AESCipher
from utils.StringUtils import message_info_to_str


class Message:
    def __init__(self, chat_id, message_info, signature):
        self.signature = signature
        self.id = str(os.urandom(8).hex())
        self.message_info = message_info
        self.chat_id = chat_id

    @staticmethod
    def send_message(chat_id, enc_key, text, sender):
        message_info = message_info_to_str(text, sender, datetime.now())
        message_info_encrypted = AESCipher(enc_key).encrypt(message_info)
        return Message(chat_id, message_info_encrypted)

    def to_dict(self):
        return {
            "id": self.id,
            "chat_id": self.chat_id,
            "message_info": self.message_info,
            "signature": self.signature
        }

    @staticmethod
    def from_dict(data_in_dic):
        message = Message.__new__(Message)
        message.id = data_in_dic["id"]
        message.chat_id = data_in_dic["chat_id"]
        message.message_info = data_in_dic["message_info"]
        message.signature = data_in_dic["signature"]
        return message
    def get_string(self):
        return f"{self.signature}|{self.date}|{self.text}|{self.sender}|{self.chatID}"

    @classmethod
    def get_from_string(cls, data_string):
        parts = data_string.split("|")

        if len(parts) != 5:
            raise ValueError("Formato de cadena no válido para crear un mensaje")

        signature, date, text, sender, chatID = parts

        return cls(text=text, sender=sender, chatID=chatID, date=date, signature=signature)