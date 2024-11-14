from config.dummy_db import chats, messages, add_message
from model.Chat import Chat
from model.Message import Message
from model.User import User


class MessageRepository:
    @staticmethod
    def getMessagesByChatID(chat_id):
        """get messages by chat ID"""
        messages_to_return = []
        for message in messages:
            if message.chat_id == chat_id:
                message_to_return = {
                    "message_info": message.message_info
                }
                messages_to_return.append(message_to_return)
        return messages_to_return

    @staticmethod
    def createMessage(chat_id, message_info) -> Message:
        """store message in db...+
            - ID
            - Message_Date_Sender (encrypted with EncKey)
            - Chat ID
            - Signature (MAC)
        """
        new_message = Message(chat_id, message_info)
        add_message(new_message)
        return new_message
