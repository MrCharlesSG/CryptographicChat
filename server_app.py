from flask_socketio import SocketIO, join_room, leave_room, rooms, emit
from flask import Flask, request, jsonify
from service.server.AuthService import ServerAuthService
from service.server.ChatService import ServerChatService

app = Flask(__name__)
app.config["SECRET_KEY"] = "super_secret_key"
socketio = SocketIO(app)


# Ruta para manejar el login
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get("username")
    if username:
        print("Receiuve ", username)
        encrypted_username = ServerAuthService.login(username)
        print("The response ", encrypted_username)
        return jsonify(encrypted_username), 200
    return jsonify({"error": "Invalid username"}), 400


# Ruta para manejar el registro
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    credentials = data.get("credentials")
    if credentials:
        to_return = ServerAuthService.register(credentials)
        return to_return, 200
    return jsonify({"error": "Invalid input"}), 400


@app.route("/api/create-chat", methods=["POST"])
def api_create_chat():
    data = request.get_json()
    sender = data.get("sender")
    receiver = data.get("receiver")
    if sender and receiver:
        created_chat = ServerChatService.create_chat(sender, receiver)
        receiver_info = created_chat["receiver"]
        receiver_username = created_chat["receiver_username"]
        print("The receiver ", receiver_username)
        # send to other
        socketio.emit("new-chat", receiver_info, room=receiver_username)

        return created_chat["sender"], 200
    return jsonify({"error": "Invalid input"}), 400


@app.route("/api/chats", methods=["POST"])
def api_get_chats():
    data = request.get_json()
    username = data.get("username")
    if username:
        print("Receiuve ", username)
        chats = ServerChatService.get_chats(username)
        print("The response ", chats)
        return chats, 200
    return jsonify({"error": "Invalid username"}), 400


@app.route("/api/new-message", methods=["POST"])
def api_new_message():
    data = request.get_json()
    message_header = data.get("message_header")
    chat_metadata = data.get("chat_metadata")
    message = data.get("message")
    if message_header and chat_metadata and message:
        print("Receiuve message ", chat_metadata)
        message = ServerChatService.send_message(message_header, chat_metadata, message, None)
        print("The response ", message)

        receiver_username = message["receiver_username"]
        socketio.emit("new-message", message["receiver"], room=receiver_username)

        return message["sender"], 200

    return jsonify({"error": "Invalid message info"}), 400


@socketio.on("connect")
def handle_connect():
    print("Client connected")


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")


@socketio.on("join")
def on_join(data):
    username = data["username"]
    join_room(username)
    print(f"{username} joined room")


@socketio.on("leave")
def on_leave(data):
    username = data["username"]
    leave_room(username)
    print(f"{username} left room")


if __name__ == "__main__":
    socketio.run(app, debug=True, port=5000)
