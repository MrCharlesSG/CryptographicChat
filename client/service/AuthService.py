from cipher.AESCipher import AESCipher
from cipher.RSACipher import RSACipher
from client.model.DecryptedChat import DecryptedChat
from server.config.dummy_db import server_private_key
from utils.StringUtils import credentials_to_str


class ClientAuthService:
    @staticmethod
    def send_login(username, server_public_key):  #encrypted with spbk
        """
        1. encrypt username with spbk
        2. send to server
        """
        encrypted_username = RSACipher.encrypt(username, server_public_key)
        """# send to server
        returned_from_server = ServerAuthService.login(encrypted_username)
        return returned_from_server"""
        return {
            "username": encrypted_username
        }

    @staticmethod
    def receive_login(returned_from_server, password, server_public_key):  #encrypted with spbk
        """
        receive
            PrK (encrypted with password),
            Bob's PbK (encrypted with Bob's PbK),
            chats:
                chat_id (encripted with EncKey),
                User1_PbK (encrypted with EncKey),
                EncKey_User2 (encrypted with Bob's PbK),
                User1_username (encrypted with EncKey)
                messages:
                    Message_Date_Sender (encrypted with EncKey),
        """
        signature = returned_from_server.pop("signature")
        prk_from_server = returned_from_server["prk"]
        pbk_from_server = returned_from_server["pbk"]
        enc_key_from_server = returned_from_server["enc_key"]

        if not RSACipher.verify_signature(prk_from_server, signature, server_public_key):
            raise Exception("Response was corrupted")

        from_server_prk = AESCipher(password).decrypt(prk_from_server)
        from_server_enc_key = RSACipher().decrypt(enc_key_from_server, from_server_prk)
        from_server_pbk = AESCipher(from_server_enc_key).decrypt(pbk_from_server)
        chats = []
        if "chats" in returned_from_server:
            for encrypted_chat in returned_from_server["chats"]:
                from_server_chat = DecryptedChat(encrypted_chat, from_server_enc_key)
                chats.append(from_server_chat)

        return {
            "private_key_to_store": from_server_prk,
            "server_enc_key": from_server_enc_key,
            "public_key": from_server_pbk,
            "chats": chats
        }

    @staticmethod
    def send_register(username, password, server_public_key):
        """
        receive encrypted username and password with spbk and
            1. encrypt username and password with spbk
            2. send
        """
        credentials_str = credentials_to_str(username, password)
        encrypted_credentials = RSACipher.encrypt(credentials_str, server_public_key)
        return {
            "credentials": encrypted_credentials
        }

    @staticmethod
    def receive_register(returned_from_server, password, server_public_key):  #encrypted with spbk
        """
        receive encrypted username and password with spbk and
            1. check signature
            2. decrypt prk with password
            3. decrypt pbk with prk
            4. decrypt username
            
        """
        signature = returned_from_server.pop("signature")
        from_server_prk = returned_from_server["prk"]
        from_server_enc_key = returned_from_server["enc_key"]
        from_server_pbk = returned_from_server["pbk"]
        from_server_username = returned_from_server["username"]

        if not RSACipher.verify_signature(from_server_prk, signature, server_public_key):
            raise Exception("Response was corrupted")

        prk = AESCipher(password).decrypt(from_server_prk)
        enc_key = RSACipher().decrypt(from_server_enc_key, prk)
        aes = AESCipher(enc_key)
        pbk = aes.decrypt(from_server_pbk)
        username = aes.decrypt(from_server_username)
        return {
            "private_key_to_store": prk,
            "server_enc_key": enc_key,
            "public_key": pbk,
            "username": username,
        }


"""
encr = ClientAuthService.send_login("Alice")
encrBoB = ClientAuthService.send_login("Bob")
retA = ServerAuthService.login(encr['username'])
retABob = ServerAuthService.login(encrBoB['username'])
ClientAuthService.receive_login(retABob, "user")
ClientAuthService.receive_login(retA, "user")


encr = ClientAuthService.send_register("cser", "user")
ret = ServerAuthService.register(encr['credentials'])
ClientAuthService.receive_register(ret, "user")
"""