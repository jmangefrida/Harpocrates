'''
cmd.py
'''
from cryptography.fernet import InvalidToken
from srv.store import Store
from srv.user import User
from enc import KeyKeeper
from srv.auth import Secret, Client, Role


class Cmd(object):
    """docstring for Cmd"""
    def __init__(self, keeper, store):
        self.store = store
        self.counter = 0
        self.keeper = keeper

    def register_img(self, img_name, role_name,  username, password, pub_key):
        try:
            user = User.load(username, self.store)
            self.keeper.check_pass(password, user.salt, user.enc_key)
            print("user")
            # print(user.salt)
            # print(r)
            print(user.enc_key)
        except InvalidToken as e:
            # print(repr(e))
            print("password invalid")
            return False
        self._save_img(img_name, role_name, pub_key)
        return True

    def _save_img(self, img_name, role_name, pub_key):
        print("image registered")
        pass
