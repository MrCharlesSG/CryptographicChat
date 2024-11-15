def credentials_to_str(username, password):
    return f"{username}|{password}"


def credentials_from_str(credentials):
    parts = credentials.split("|")

    if len(parts) != 2:
        raise ValueError("Formato credenciales incorrectas")

    username, password = parts
    return username, password


def message_info_to_str(text, sender, date) -> str:
    return f"{text}|{sender}|{date}"


def message_info_from_str(message_info):
    parts = message_info.split("|")

    if len(parts) != 3:
        raise ValueError("Formato mensaje incorrecto")

    text, sender, date = parts
    return text, sender, date


def create_chat_info_to_str(sender_username, other_party_username):
    return f"{sender_username}, {other_party_username}"


def create_chat_info_from_str(create_chat_info):
    parts = create_chat_info.split("|")

    if len(parts) != 3:
        raise ValueError("Formato mensaje incorrecto")

    sender_username, other_party_username = parts
    return sender_username, other_party_username


def chat_metadata_to_str(receiver, chat_id):
    return f"{receiver}|{chat_id}"


def chat_metadata_from_str(chat_metadata):
    parts = chat_metadata.split("|")

    if len(parts) != 2:
        raise ValueError("Formato chat metadata incorrecto")

    receiver, chat_id = parts
    return receiver, chat_id


def chat_metadata_to_receive_to_str(chat_metadata, user_sender_public_key):
    return f"{chat_metadata}|{user_sender_public_key}"


def chat_metadata_to_receive_from_str(chat_metadata):
    parts = chat_metadata.split("|")

    if len(parts) != 3:
        raise ValueError("Formato chat metadata to receive incorrecto")

    receiver, chat_id, user_sender_public_key = parts
    return receiver, chat_id, user_sender_public_key
