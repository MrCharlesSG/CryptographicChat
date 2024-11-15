from datetime import datetime

from cipher.AESCipher import AESCipher
from cipher.RSACipher import RSACipher
from client.model.DecryptedChat import DecryptedChat
from utils.StringUtils import chat_metadata_to_str, \
    message_info_to_str, message_info_from_str, chat_metadata_to_receive_from_str


class ClientChatService:

    @staticmethod
    def send_create_chat(username, other_party_username, server_public_key, server_enc_key):
        """
        prepare info to send
        1. encrypt usernames
        2. create signature
        """
        encryption_sender = RSACipher.encrypt(username, server_public_key)
        encryption_receiver = AESCipher(server_enc_key).encrypt(other_party_username)
        return {
            "sender": encryption_sender,
            "receiver": encryption_receiver
        }

    @staticmethod
    def receive_create_chat(chat_from_server, server_enc_key):
        """
        decrypt create_chat response
        1. check server-signature
        2. decrypt chat info
        3. return chat
        """
        # use to chek signature
        print("Chat from server ", chat_from_server)
        decrypted_chat = DecryptedChat({"chat_info": chat_from_server}, server_enc_key, None)
        return decrypted_chat

    @staticmethod
    def send_get_chats(username, server_enc_key):
        """
        encrytpt username with server_enc_key
        """
        return AESCipher(server_enc_key).encrypt(username)

    @staticmethod
    def send_message(server_public_key, sender_username, receiver_username, chat_id,
                     text, chat_enc_key, server_enc_key, user_private_key):
        """
        1. encrypt sender_username with SPbK
        2. encrrypt metadata (chat and receiver)
        3. create message message_info_to_str
        4. encrypt message with chat_enc_key
        5. encrypt message with server_enc_key
        6. send
            {
                message_header,
                chat_metadata,
                message_info
        """
        message_header = RSACipher.encrypt(sender_username, server_public_key)

        chat_metadata = chat_metadata_to_str(receiver_username, chat_id)
        encrypted_chat_metadata = AESCipher(server_enc_key).encrypt(chat_metadata)

        message_info = message_info_to_str(text, sender_username, datetime.now())
        encrypted_message_info = AESCipher(chat_enc_key).encrypt(message_info)
        signature = RSACipher.sign(encrypted_message_info, user_private_key)
        print("Sig ", signature)
        print("prk ", user_private_key)
        print("mes ", encrypted_message_info)
        encrypted_message_info = AESCipher(server_enc_key).encrypt(encrypted_message_info)

        return {
            "message_header": message_header,
            "chat_metadata": encrypted_chat_metadata,
            "message": encrypted_message_info,
            "signature": signature
        }

    @staticmethod
    def get_chat_by_id(chat_id, chats) -> DecryptedChat | None:
        for chat_it in chats:
            if chat_it["chat_id"] == chat_id:
                return DecryptedChat.from_dict(chat_it)
        return None

    @staticmethod
    def receive_new_message(response, chats, server_enc_key):
        """
        1. decrypt metadata
        2. decrypt chat with server_enc_key and chat_keys[chat.id]
        3. message_text = message_info_from_str
        4. return {
            chat_id
            message_text
            message_date
            sender
        """

        meta_data = response["meta_data"]
        message = response["message"]
        message_signature = response["signature"]
        metadata_decrypted = AESCipher(server_enc_key).decrypt(meta_data)
        receiver, chat_id, sender_public_key = chat_metadata_to_receive_from_str(metadata_decrypted)

        chat_json = chats[chat_id]
        if chat_json is None:
            raise Exception("Chat id is incorrect probably Zelda is here")

        chat = DecryptedChat.from_dict(chat_json)
        chat_key = chat.enc_key
        message_decrypted = AESCipher(server_enc_key).decrypt(message)
        print("Sig ", message_signature)
        print("prk ", sender_public_key)
        print("mes ", message_decrypted)
        if not RSACipher.verify_signature(message_decrypted, message_signature, sender_public_key):
            raise Exception("Message has suffer violation, or the sender is not the right one")

        message_decrypted = AESCipher(chat_key).decrypt(message_decrypted)

        text, sender, date = message_info_from_str(message_decrypted)
        return chat, text, sender, date
