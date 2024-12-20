'''
cmd.py
'''
from cryptography.fernet import InvalidToken
from srv.store import Store
from srv.user import User
from enc import KeyKeeper
from srv.auth import Secret, Client, Role, Image
from datetime import datetime


class Cmd(object):
    """docstring for Cmd"""
    def __init__(self, keeper, store):
        self.store = store
        self.counter = 0
        self.keeper: KeyKeeper = keeper

    def register_img(self, img_name, role_name,  username, password, pub_key):
        try:
            user = User.load(username, self.store)
            self.keeper.check_pass(password, user.salt, user.enc_key)
            role = Role.load(role_name, self.store)
            print("user")
            # print(user.salt)
            # print(r)
            print(user.enc_key)
        except InvalidToken as e:
            # print(repr(e))
            print("password invalid")
            return False
        self._save_img(img_name, role_name, username, pub_key)
        return True

    def _save_img(self, img_name, role_name, username, pub_key):

        Image.new(img_name, datetime.now(), username, role_name, pub_key, self.store)
        print("image registered")
        pass

    def auth_img(self, img_name):
        img = Image.load(img_name, self.store)
        data = img.start_authenticate()
        cipher = KeyKeeper.encrypt_with_client_key(data, img.public_key)
        return cipher, img

    def auth_client(self, client_name):
        client = Client.load(client_name, self.store)
        data = client.start_authenticate()
        cipher = KeyKeeper.encrypt_with_client_key(data, client.public_key)
        return cipher, client

    def register_client(self, client_name, client_ip, img_name, pub_key):
        client = Client.new(client_name, client_ip, img_name, pub_key, self.store)
        return True

    def request_secret(self, secret_name, client):
        img = Image.load(client.image_name, self.store)
        role = Role.load(img.role, self.store)
        secret = role.request(secret_name)
        secret.prepared_secret = self.keeper.prepare_secret(secret.secret, client.public_key)
        return secret

    def create_secret(self, secret_name, account_name, account_pass, description):
        account_secret = self.keeper.encrypt_secret(account_pass)
        secret = Secret.new(secret_name, account_name, account_secret, description, self.store)

    def grant(self, role_name, secret_name):
        secret = Secret.load(secret_name, self.store)
        role = Role.load(role_name, self.store)
        role.grant(secret.name)


