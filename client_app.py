import socket

import requests
import socketio
from flask import Flask, request, jsonify
from flask import render_template, redirect, url_for
from flask_socketio import SocketIO

from config.dummy_db import server_public_key
from model.DecryptedChat import DecryptedChat
from service.client.AuthService import ClientAuthService
from service.client.ChatService import ClientChatService

app = Flask(__name__)
app.config["SECRET_KEY"] = "super_secret_key"

session = {}


def find_available_port(start_port=5001, max_port=5100):
    local_port = start_port
    while local_port <= max_port:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("localhost", local_port)) != 0:
                return local_port
        local_port += 1
    raise RuntimeError("No available ports found in the specified range.")


port = find_available_port()
"""
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_REDIS"] = StrictRedis(host="localhost", port=6379, db=0)
app.config["SESSION_KEY_PREFIX"] = f"flask_session_{port}_"
"""

API_SERVER_URL = "http://localhost:5000"
server_sio = socketio.Client()
frontend_sio = SocketIO(app)

#Session(app)
#frontend_sio = SocketIO(app)


API_CLIENT_HOST = f"http://localhost:{port}"

'''
REST API
'''


def is_authenticated():
    return "private_key" in session


def is_authenticate_then_redirect():
    if is_authenticated():
        return redirect(url_for("chat"))


@app.route("/login", methods=["GET"])
def login():
    is_authenticate_then_redirect()
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    username = request.form.get("username")
    if username:
        send_to_login = ClientAuthService.send_login(username)
        print("Sended to login", send_to_login)
        response = requests.post(f"{API_SERVER_URL}/api/login", json=send_to_login)
        print("The response ", response)
        if response.status_code == 200:
            session["temporal_server_data"] = response.json()
            session["username"] = username
            return jsonify({"success": True}), 200
    return jsonify({"success": False, "error": "Invalid username"}), 400


@app.route("/login/set-password", methods=["GET", "POST"])
def login_set_password():
    if request.method == "GET":
        is_authenticate_then_redirect()
        if "temporal_server_data" not in session:
            return redirect(url_for("login"))
        return render_template("repeat-password.html")

    password = request.form.get("password")
    print("The password ", password, "The session ", session)
    if "temporal_server_data" in session:
        server_data = session.pop("temporal_server_data")
        print("The session ", session)
        rtn = ClientAuthService.receive_login(server_data, password)
        print("The decrypted things ", rtn)
        session["private_key"] = rtn["private_key"]
        session["server_enc_key"] = rtn["server_enc_key"]
        session["public_key"] = rtn["public_key"]
        session["chats"] = {chat_it.chat_id: chat_it.to_dict() for chat_it in rtn["chats"]}
        print("The chats", session["chats"])
        print("The session ", session)
        return jsonify({"success": True}), 200

    return jsonify({"success": False}), 400


# Ruta para mostrar la página de registro
@app.route("/register", methods=["GET"])
def register():
    is_authenticate_then_redirect()
    return render_template("register.html")


@app.route("/api/register", methods=["POST"])
def api_register():
    username = request.form.get("username")
    password = request.form.get("password")
    if username and password:
        cred = ClientAuthService.send_register(username, password)
        print("registersing ", cred)
        response = requests.post(f"{API_SERVER_URL}/api/register", json=cred)
        print("response ", response)
        if response.status_code == 200:
            session["temporal_server_data"] = response.json()
            return jsonify({"success": True}), 200
    return jsonify({"success": False, "error": "Invalid input"}), 400


@app.route("/api/logout", methods=["DELETE"])
def logout():
    if is_authenticated():
        if server_sio.connected:
            server_sio.emit("leave", {"username": session["username"]})
            server_sio.disconnect()

        session.pop("private_key")
        session.pop("server_enc_key")
        session.pop("public_key")
        session.pop("username")
        if "chats" in session:
            session.pop("chats")

        return jsonify({"success": True}), 200

    return jsonify({"success": False, "error": "User Not Authenticated"}), 400


@app.route("/register/repeat-password", methods=["GET", "POST"])
def register_repeat_password():
    if request.method == "GET":
        is_authenticate_then_redirect()
        if "temporal_server_data" not in session:
            return redirect(url_for("login"))
        return render_template("repeat-password.html")

    password = request.form.get("password")
    print("The password ", password)
    if "temporal_server_data" in session:
        server_data = session.pop("temporal_server_data")
        rtn = ClientAuthService.receive_register(server_data, password)
        print("The decrypted things ", rtn)
        session["private_key"] = rtn["private_key"]
        session["server_enc_key"] = rtn["server_enc_key"]
        session["public_key"] = rtn["public_key"]
        session["username"] = rtn["username"]
        session["chats"] = {}
        return jsonify({"success": True}), 200

    return jsonify({"success": False}), 400


@app.route("/", methods=["GET"])
def chat():
    if not is_authenticated():
        return redirect(url_for("login"))

    if is_authenticated():
        username = session["username"]

        if not server_sio.connected:
            server_sio.connect(API_SERVER_URL)
            server_sio.emit("join", {"username": username})

        return render_template("chat.html", username=username, chats=session["chats"])


@app.route("/api/create-chat", methods=["POST"])
def create_chat():
    if not is_authenticated():
        return jsonify({"success": False}), 403
    receiver_username = request.form.get("username")
    print("The other username ", receiver_username)
    if receiver_username:
        to_send = ClientChatService.send_create_chat(session["username"], receiver_username,
                                                     server_public_key, session["server_enc_key"])
        print("creating chat ", to_send)
        response = requests.post(f"{API_SERVER_URL}/api/create-chat", json=to_send)
        print("response ", response)
        if response.status_code == 200:
            decrypted_chat = ClientChatService.receive_create_chat(response.json(), session["server_enc_key"])
            session["chats"][decrypted_chat.chat_id] = decrypted_chat.to_dict()
            print("The new chat in chats ", session["chats"][decrypted_chat.chat_id])
            return jsonify({"success": True}), 200

    return jsonify({"success": False}), 400


@app.route("/api/create-message", methods=["POST"])
def send_message():
    if not is_authenticated():
        return jsonify({"success": False}), 403

    data = request.get_json()
    chat_id = data.get("chat_id")
    text = data.get("text")
    chat_with_id = DecryptedChat.from_dict(session["chats"][chat_id])
    print("the chatr of the message ", chat_with_id)
    if chat_with_id is not None:
        to_send = ClientChatService.send_message(
            server_public_key, session["username"], chat_with_id.other_username, chat_id,
            text, chat_with_id.enc_key, session["server_enc_key"]
        )
        print("sending message ", to_send)
        response = requests.post(f"{API_SERVER_URL}/api/new-message", json=to_send)
        print("response ", response)
        if response.status_code == 200:
            decrypted_message = ClientChatService.receive_new_message(response.json(), session["chats"],
                                                                      session["server_enc_key"])
            _, text, sender, date = decrypted_message
            chat_with_id.add_new_message(text, sender, date)
            session["chats"][chat_id] = chat_with_id.to_dict()
            print("The new chat after message", session["chats"][chat_id])
            return chat_with_id.to_dict(), 200
    return jsonify({"success": False}), 400


"""
Socket
"""


@server_sio.on("new-chat")
def handle_new_chat(data):
    decrypted_chat = ClientChatService.receive_create_chat(data, session["server_enc_key"])
    session["chats"][decrypted_chat.chat_id] = decrypted_chat.to_dict()
    print("New chat received:", decrypted_chat.to_dict())
    #frontend_sio.emit("new-chat")
    frontend_sio.emit("update-chats", {"message" :"new chat"})


@server_sio.on("new-message")
def handle_new_message(data):
    print("The new message encrypted", data)
    decrypted_message = ClientChatService.receive_new_message(data, session["chats"],
                                                              session["server_enc_key"])
    chat_with_id, text, sender, date = decrypted_message
    chat_with_id.add_new_message(text, sender, date)
    session["chats"][chat_with_id.chat_id] = chat_with_id.to_dict()
    print("The new message in chat socket", session["chats"][chat_with_id.chat_id])
    #frontend_sio.emit("new-message")
    frontend_sio.emit("update-messages", {"message" :"new message"})


if __name__ == "__main__":
    print(f"Starting client app on port {port}")
    frontend_sio.run(app, port=port, debug=True)
