from cipher.AESCipher import AESCipher
from server.config.dummy_db import chats, add_chat
from server.dal.MessageRepository import MessageRepository
from server.model.Chat import Chat
from server.model.User import User


class ChatRepository:
    @staticmethod
    def getChatsByUserPublicKey(user_pbk_for_server, user: User, server_private_key):
        """get chats by UPbK by generating the salt and chking out the chats"""
        # find users chat
        chats_to_return = []
        print("The chats ", chats)
        for chat in chats:
            if chat.user1_pbk_for_server == user_pbk_for_server:
                enc_key_user = chat.enc_key_user1
                participant_info = chat.participant_info_user2
                messages = MessageRepository.getMessagesByChatID(chat.chat_id)
                chat_id_encrypted = AESCipher(user.get_decrypted_server_enc_key(server_private_key)).encrypt(chat.chat_id)
                chat_to_add = {
                    "chat_info": {
                        "chat_id": chat_id_encrypted,
                        "enc_key": enc_key_user,
                        "participant_info": participant_info
                    },
                    "messages": messages
                }
                chats_to_return.append(chat_to_add)
            elif chat.user2_pbk_for_server == user_pbk_for_server:
                enc_key_user = chat.enc_key_user2
                participant_info = chat.participant_info_user1
                messages = MessageRepository.getMessagesByChatID(chat.chat_id)
                chat_id_encrypted = AESCipher(user.get_decrypted_server_enc_key(server_private_key)).encrypt(chat.chat_id)
                chat_to_add = {
                    "chat_info": {
                        "chat_id": chat_id_encrypted,
                        "enc_key": enc_key_user,
                        "participant_info": participant_info
                    },
                    "messages": messages
                }
                chats_to_return.append(chat_to_add)

        return chats_to_return

    @staticmethod
    def getChatByID(id) -> Chat | None:
        """get chats by ID"""
        print("The chats ", chats)
        for chat in chats:
            if chat.chat_id == id:
                return chat

        return None

    @staticmethod
    def chat_exists_by_id(id_chat) -> bool:
        for chat in chats:
            if chat.chat_id == id_chat:
                return True

        return False

    @staticmethod
    def chatExists(user1_pbk_for_server, user2_pbk_for_server):
        print("The chats ", chats)
        for chat in chats:
            if ((chat.user1_pbk_for_server == user1_pbk_for_server
                 and chat.user2_pbk_for_server == user2_pbk_for_server)
                    or (chat.user2_pbk_for_server == user1_pbk_for_server
                        and chat.user1_pbk_for_server == user2_pbk_for_server)):
                return True
        return False

    @staticmethod
    def createChat(user1_pbk_for_server, user2_pbk_for_server, user_1: User, user_2: User) -> Chat:
        """store chat in database, generating salt...+
            - User1_PbK_for_server (encrypted with PBKDF2)
            - User2_PbK_for_server (encrypted with PBKDF2)
            - EncKey_User1 (encrypted with User1_PbK)
            - EncKey_User2 (encrypted with User2_PbK)
            - ParticipantInfo_User1 (encrypted with EncKey)
            - ParticipantInfo_User2 (encrypted with EncKey)
        """
        created_chat = Chat.create_chat(user1_pbk_for_server, user2_pbk_for_server, user_1, user_2)
        add_chat(created_chat)
        return created_chat

