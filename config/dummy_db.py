import json
import os

from model.Chat import Chat
from model.Message import Message
from model.User import User

script_dir = os.path.dirname(os.path.realpath(__file__))

# Construct the full path for data.json
data_file_path = os.path.join(script_dir, 'data.json')


# Función para guardar los datos en el archivo JSON
def save_data():
    data = {
        "users": [user.to_dict() for user in users],
        "chats": [chat.to_dict() for chat in chats],
        "messages": [message.to_dict() for message in messages],
        "server_pbk": server_public_key,
        "server_prk": server_private_key,
    }

    with open(data_file_path, "w") as json_file:
        json.dump(data, json_file, indent=4)


with open(data_file_path, "r") as json_file:
    data = json.load(json_file)

server_public_key = data["server_pbk"]
server_private_key = data["server_prk"]

users = [User.from_dict(user_data) for user_data in data["users"]]

chats = [Chat.from_dict(chat_data) for chat_data in data["chats"]]

messages = [Message.from_dict(message_data) for message_data in data["messages"]]


def add_user(user):
    users.append(user)
    save_data()


def remove_user(user_id):
    global users
    users = [user for user in users if user.id != user_id]
    save_data()


def add_chat(chat):
    chats.append(chat)
    save_data()


def remove_chat(chat_id):
    global chats
    chats = [chat for chat in chats if chat.id != chat_id]
    save_data()


def add_message(message):
    messages.append(message)
    save_data()


def remove_message(message_id):
    global messages
    messages = [message for message in messages if message.id != message_id]
    save_data()
