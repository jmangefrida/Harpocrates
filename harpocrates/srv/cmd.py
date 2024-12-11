'''
cmd.py
'''
from srv.store import Store
from srv.user import User
from enc import KeyKeeper
from srv.auth import Secret, Client, Role


class Cmd(object):
    """docstring for Cmd"""
    def __init__(self):
        # self.store = Store()
        self.counter = 0

    def register_img(self, username, password, image_name):
        try:
            store = Store()
            user = User.load(username, store)
            print("user")
        except Exception as e:
            print(repr(e))
            return False