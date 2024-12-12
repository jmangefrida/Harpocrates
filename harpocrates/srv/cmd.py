'''
cmd.py
'''
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

    def register_img(self, username, password, image_name):
       # try:
            user = User.load(username, self.store)
            r = self.keeper.check_pass(password, user.salt, user.enc_key)
            print("user")
            # print(user.salt)
            print(r)
            print(user.enc_key)
            return r
       # except Exception as e:
            #print(repr(e))
            return False