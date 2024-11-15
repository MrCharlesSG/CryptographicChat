from cipher.AESCipher import AESCipher
from cipher.PBKDF2Cipher import PBKDF2Cipher
from cipher.RSACipher import RSACipher
from server.config.dummy_db import server_private_key
from server.dal.ChatRepository import ChatRepository
from server.dal.MessageRepository import MessageRepository
from server.dal.UserRepository import UserRepository
from utils.StringUtils import chat_metadata_from_str, chat_metadata_to_str, chat_metadata_to_receive_to_str


class ServerChatService:

    @staticmethod
    def get_chats(encrypted_username):
        decrypted_username = RSACipher.decrypt(encrypted_username, server_private_key)
        user = UserRepository.getUserByUsername(decrypted_username)

        user_pbk_for_server = PBKDF2Cipher(user.get_decrypted_server_enc_key(server_private_key),
                                           server_private_key).derive()
        chats = ChatRepository.getChatsByUserPublicKey(user_pbk_for_server, user)
        return {
            "chats": chats
        }

    @staticmethod
    def create_chat(encrypted_sender, encrypted_receiver):
        """
        Create a chat with the given encrypted users
            1. sender_username = decrypt(encrypted_sender, sprk)
            2. receiver_username = decrypt(encrypted_receiver, user_enc_key)
            3. getPbK of receiver_username
            4. Encrypt Users PbK For Server
            5. check if chat exists
            6. create chat and store
            7. notify other party by socket
            8. returns

            returns and notification return= {
                encrypted_chat_id (encrypted with EncKey)
                ParticipantInfo_User (encrypted with EncKey),
                EncKey_User (encrypted with BPbK),
            }
        """
        sender_username = RSACipher.decrypt(encrypted_sender, server_private_key)
        user_sender = UserRepository.getUserByUsername(sender_username)
        aes_sender = AESCipher(user_sender.get_decrypted_server_enc_key(server_private_key))

        receiver_username = aes_sender.decrypt(encrypted_receiver)
        user_receiver = UserRepository.getUserByUsername(receiver_username)
        aes_receiver = AESCipher(user_receiver.get_decrypted_server_enc_key(server_private_key))

        if user_receiver is None:
            raise Exception("Other user does not exists")

        user1_pbk_for_server = PBKDF2Cipher(user_sender.get_decrypted_server_enc_key(server_private_key),
                                            server_private_key).derive()
        user2_pbk_for_server = PBKDF2Cipher(user_receiver.get_decrypted_server_enc_key(server_private_key),
                                            server_private_key).derive()

        if ChatRepository.chatExists(user1_pbk_for_server, user2_pbk_for_server):
            raise Exception("You have already this chat")

        create_chat = ChatRepository.createChat(user1_pbk_for_server, user2_pbk_for_server, user_sender,
                                                user_receiver)

        chat_id_for_sender = aes_sender.encrypt(create_chat.chat_id)
        chat_id_for_receiver = aes_receiver.encrypt(create_chat.chat_id)
        return {
            "sender": {
                "chat_id": chat_id_for_sender,
                "enc_key": create_chat.enc_key_user1,
                "participant_info": create_chat.participant_info_user2
            },
            "receiver_username": user_receiver.username,
            "receiver": {
                "chat_id": chat_id_for_receiver,
                "enc_key": create_chat.enc_key_user2,
                "participant_info": create_chat.participant_info_user1
            }
        }

    @staticmethod
    def send_message(message_header_encrypted, meta_data_encrypted, message_encrypted, message_signature):
        """
        1. decrypt sender
        2. get user_sender by username
        3. decrypt metadata
        4. check signature
        4. find chat and user_sender and check if chat is of users
        5. decrypt message and encrypt for receiver
        6. store message
        """
        sender_username_decrypted = RSACipher.decrypt(message_header_encrypted, server_private_key)
        user_sender = UserRepository.getUserByUsername(sender_username_decrypted)

        aes_of_sender = AESCipher(user_sender.get_decrypted_server_enc_key(server_private_key))
        meta_data_decrypted = aes_of_sender.decrypt(meta_data_encrypted)
        receiver, chat_id = chat_metadata_from_str(meta_data_decrypted)
        print("The metadata ", receiver, chat_id)
        user_receiver = UserRepository.getUserByUsername(receiver)

        if user_receiver is None:
            raise Exception("User receiver does not exists")

        if not ChatRepository.chat_exists_by_id(chat_id):
            raise Exception("Chat does not exists")

        message = aes_of_sender.decrypt(message_encrypted)

        if not RSACipher.verify_signature(message, message_signature, user_sender.public_key):
            raise Exception("Message has suffer violation, or the sender is not the right one")

        new_message = MessageRepository.createMessage(chat_id, message, message_signature)

        aes_of_receiver = AESCipher(user_receiver.get_decrypted_server_enc_key(server_private_key))
        new_message_for_receiver = aes_of_receiver.encrypt(new_message.message_info)
        meta_data_to_receive = chat_metadata_to_receive_to_str(meta_data_decrypted, user_sender.public_key)
        meta_data_for_receiver = aes_of_receiver.encrypt(meta_data_to_receive)

        meta_data_for_sender = chat_metadata_to_str(user_sender.username, chat_id)
        meta_data_for_sender = chat_metadata_to_receive_to_str(meta_data_for_sender, user_sender.public_key)
        meta_data_for_sender = aes_of_sender.encrypt(meta_data_for_sender)

        return {

            "receiver_username": user_receiver.username,
            "receiver": {
                "message": new_message_for_receiver,
                "meta_data": meta_data_for_receiver,
                "signature": message_signature
            },
            "sender": {
                "message": message_encrypted,
                "meta_data": meta_data_for_sender,
                "signature": message_signature
            }
        }


"""
user = UserRepository.getUserByUsername("Bob")
private_key_to_store = AESCipher("user").decrypt(user.private_key_to_store)
server_enc_key = user.get_decrypted_server_enc_key(server_private_key)

chat = ChatRepository.getChatByID("a3c35c82fbc08046")
chat_enc_key = AESCipher(server_enc_key).decrypt(chat.enc_key_user1)

sender = RSACipher.encrypt(user.username, server_public_key)
metadata = chat_metadata_to_str("Alice", chat.chat_id)
message_info = message_info_to_str("QUe tal", user.username, datetime.now())

ewncry_metadata = AESCipher(server_enc_key).encrypt(metadata)
encr_message_info = AESCipher(chat_enc_key).encrypt(message_info)
encr_message_info = AESCipher(server_enc_key).encrypt(encr_message_info)

ServerChatService.send_message(sender, ewncry_metadata, encr_message_info, None)
"""
