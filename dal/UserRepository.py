from config.dummy_db import users, add_user
from cipher.PBKDF2Cipher import PBKDF2Cipher
from model.User import User


class UserRepository:
    @staticmethod
    def getByPublicKey(user_public_key) -> User:
        """get user by its public key"""
        for user in users:
            if user.public_key == user_public_key:
                return user

    @staticmethod
    def getUserByUsername(username):
        """get user by its username"""
        for user in users:
            if user.username == username:
                return user

        return None

    @staticmethod
    def createUser(username, password, server_public_key) -> User:
        """
        store user in db
            - PbK
            - Username
            - PrK (encrypted with password)
        """
        new_user = User.create_user(username, password, server_public_key)
        add_user(new_user)
        return new_user
