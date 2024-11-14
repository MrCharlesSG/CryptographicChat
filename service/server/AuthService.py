from cipher.AESCipher import AESCipher
from cipher.PBKDF2Cipher import PBKDF2Cipher
from cipher.RSACipher import RSACipher
from config.dummy_db import server_public_key, server_private_key
from dal.ChatRepository import ChatRepository
from dal.UserRepository import UserRepository
from utils.StringUtils import credentials_from_str, credentials_to_str


class ServerAuthService:
    @staticmethod
    def login(encrypted_username):
        """
        receive encrypted username with spbk and
            1. decrypt credentials
            2. get public key
            3. encrypt pbk with enc_key
            4. encrypt enc_key with pbk
            5. derive user (sprk, pbk) and get his chats
            6. return
                    PrK (encrypted with password),
                    Bob's PbK (encrypted with enc_key),
                    enc_key (encrypted with pbk
                    chats:
                            chat_id (encripted with EncKey),
                            User1_PbK (encrypted with EncKey),
                            EncKey_User2 (encrypted with Bob's PbK),
                            User1_username (encrypted with EncKey)
                            messages:
                                Message_Date_Sender (encrypted with EncKey),
                                Signature (MAC)
        """
        decrypted_username = RSACipher.decrypt(encrypted_username, server_private_key)
        user = UserRepository.getUserByUsername(decrypted_username)

        encrypted_public_key = (AESCipher(user.get_decrypted_server_enc_key(server_private_key))
                                .encrypt(user.public_key))
        enc_key = RSACipher.encrypt(user.get_decrypted_server_enc_key(server_private_key), user.public_key)

        encrypted_by_server_username = (AESCipher(user.get_decrypted_server_enc_key(server_private_key))
                                        .encrypt(decrypted_username))

        user_pbk_for_server = PBKDF2Cipher(user.get_decrypted_server_enc_key(server_private_key),
                                           server_private_key).derive()
        chats = ChatRepository.getChatsByUserPublicKey(user_pbk_for_server, user, server_private_key)

        to_return = {
            "prk": user.private_key,
            "pbk": encrypted_public_key,
            "enc_key": enc_key,
            "username": encrypted_by_server_username,
            "chats": chats
        }
        return to_return

    @staticmethod
    def register(encrypted_credentials):
        """
        receive encrypted username and password with spbk and
            1. decrypt credentials with spbk
            2. verify username not exists
            3. generate pbk and prk and enc_key
            4. create new user and store
            5. return
                encrypted_username (encrypted with enc_key)
                PrK (encrypted with password)
                PbK (encrypted with enc_key)
                enc_key (encrypted with pbk)
                signature
        """

        decrypted_credentials = RSACipher.decrypt(encrypted_credentials, server_private_key)
        username, password = credentials_from_str(decrypted_credentials)

        user = UserRepository.getUserByUsername(username)
        if user is not None:
            raise Exception("Username already exists")

        user = UserRepository.createUser(username, password, server_public_key)

        encrypted_user_public_key = (AESCipher(user.get_decrypted_server_enc_key(server_private_key))
                                     .encrypt(user.public_key))
        encrypted_username = AESCipher(user.get_decrypted_server_enc_key(server_private_key)).encrypt(username)
        encrypted_enc_key = RSACipher.encrypt(user.get_decrypted_server_enc_key(server_private_key), user.public_key)

        # si envio misma prk que en db zelda can infer wich has been created
        to_return = {
            "prk": user.private_key,
            "pbk": encrypted_user_public_key,
            "enc_key": encrypted_enc_key,
            "username": encrypted_username
        }
        return to_return


"""
cred = RSACipher.encrypt("Bob", server_public_key)

ServerAuthService().login(cred)"""
