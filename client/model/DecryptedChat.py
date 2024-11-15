from cipher.AESCipher import AESCipher
from cipher.RSACipher import RSACipher
from server.model.User import User
from utils.StringUtils import message_info_from_str


class DecryptedMessage:
    def __init__(self, text, sender, date):
        self.date = date
        self.sender = sender
        self.text = text

    @staticmethod
    def create_new_message(aes: AESCipher, message_info, user_public_key, participant_username,
                           participant_pbk, signature):
        decrypted_message_info = aes.decrypt(message_info)
        text, sender, date = message_info_from_str(decrypted_message_info)
        DecryptedMessage.check_message_integrity(sender, message_info, user_public_key, participant_username,
                                                 participant_pbk, signature)
        return DecryptedMessage(text, sender, date)

    @staticmethod
    def check_message_integrity(sender, message_info, user_public_key, participant_username,
                                participant_pbk, signature):

        if sender == participant_username:
            is_correct = RSACipher.verify_signature(message_info, signature, participant_pbk)
        else:
            is_correct = RSACipher.verify_signature(message_info, signature, user_public_key)
        if not is_correct:
            raise Exception("There has been a modification in the messages")

    def to_dict(self):
        """Convert message to dictionary."""
        return {
            "date": self.date,
            "sender": self.sender,
            "text": self.text
        }

    @staticmethod
    def from_dict(data):
        """Create DecryptedMessage from dictionary."""
        return DecryptedMessage(data["text"], data["sender"], data["date"])


class DecryptedChat:
    def __init__(self, chat_from_server, server_enc_key, user_pbk, user_prk):
        print(chat_from_server)
        chat_info_from_server = chat_from_server["chat_info"]
        server_aes = AESCipher(server_enc_key)
        self.chat_id = server_aes.decrypt(chat_info_from_server["chat_id"])
        enc_key_encrypted = server_aes.decrypt(chat_info_from_server["enc_key"])
        self.enc_key = RSACipher.decrypt(enc_key_encrypted, user_prk)
        self.aes = AESCipher(self.enc_key)
        participant_info_encrypted = server_aes.decrypt(chat_info_from_server["participant_info"])
        participant_info_decrypted = self.aes.decrypt(participant_info_encrypted)
        self.other_username, self.other_pbk = User.get_from_info(participant_info_decrypted)
        self.messages = []

        if "messages" in chat_from_server:
            messages_from_server = chat_from_server["messages"]
            for message_from_server in messages_from_server:
                self.messages.append(DecryptedMessage.create_new_message(
                    self.aes, message_from_server["message_info"], user_pbk, self.other_username,
                    self.other_pbk, message_from_server["signature"]
                ))

    def add_new_message(self, text, sender, date):
        self.messages.append(DecryptedMessage(text, sender, date))

    def to_dict(self):
        """Convert chat to dictionary."""
        return {
            "chat_id": self.chat_id,
            "enc_key": self.enc_key,
            "other_username": self.other_username,
            "other_pbk": self.other_pbk,
            "messages": [message.to_dict() for message in self.messages]
        }

    @staticmethod
    def from_dict(data):
        """Create DecryptedChat from dictionary."""
        decrypted_chat = DecryptedChat.__new__(DecryptedChat)
        decrypted_chat.chat_id = data["chat_id"]
        decrypted_chat.enc_key = data["enc_key"]
        decrypted_chat.other_username = data["other_username"]
        decrypted_chat.other_pbk = data["other_pbk"]
        decrypted_chat.messages = [DecryptedMessage.from_dict(m) for m in data["messages"]]
        decrypted_chat.aes = AESCipher(decrypted_chat.enc_key)
        return decrypted_chat
