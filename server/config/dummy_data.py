import json

from cipher.RSACipher import RSACipher
from server.model.Chat import Chat
from server.model.Message import Message
from server.model.User import User

# Datos de prueba de usuario (usando la clase RSACipher)


server_private_key, server_public_key = RSACipher.generate_keys()

user1 = User.create_user("Bob", "user", server_public_key)
print("User created ", user1.username)
user2 = User.create_user("Alice", "user", server_public_key)
print("User created ", user2.username)
user3 = User.create_user("Caesar", "user", server_public_key)
print("User created ", user1.username)
user4 = User.create_user("Daniel", "user", server_public_key)

chat1 = Chat(user1, user2, server_private_key)
print("Chat created ", chat1.get_chat_str(user1))
chat2 = Chat(user1, user3, server_private_key)
print("Chat created ", chat2.get_chat_str(user3, False))

message1 = Message.send_message(chat1.chat_id, chat1.enc_key_real, "Que tal", user1.username)
print("!Cerated chat")
message2 = Message.send_message(chat1.chat_id, chat1.enc_key_real, "Bien y TU?", user2.username)
print("!Cerated chat")
message3 = Message.send_message(chat1.chat_id, chat1.enc_key_real, "No me quejo", user1.username)
print("!Cerated chat")
message4 = Message.send_message(chat2.chat_id, chat2.enc_key_real, "Hola cesar", user1.username)
print("!Cerated chat")
message5 = Message.send_message(chat2.chat_id, chat2.enc_key_real, "Hola bob", user3.username)
print("!Cerated chat")
message6 = Message.send_message(chat2.chat_id, chat2.enc_key_real, "que talk estas", user3.username)
print("!Cerated chat")
message7 = Message.send_message(chat2.chat_id, chat2.enc_key_real, "bn", user1.username)
print("!Cerated chat")

data = {
    "users": [user1.to_dict(), user2.to_dict(), user3.to_dict(), user4.to_dict()],
    "chats": [chat1.to_dict(), chat2.to_dict()],
    "messages": [message1.to_dict(), message2.to_dict(), message3.to_dict(), message4.to_dict(), message5.to_dict(),
                 message6.to_dict(), message7.to_dict()],
    "server_pbk": server_public_key,
    "server_prk":server_private_key,
}

with open("data.json", "w") as json_file:
    json.dump(data, json_file, indent=4)
