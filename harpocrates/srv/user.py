'''
user.py
'''
from os import stat
from store import Store
from datetime import datetime


class User():

    def __init__(self,
                 username,
                 salt,
                 password,
                 register_date,
                 last_pass_change,
                 account_type,
                 store):
        self.username = username
        self.salt = salt
        self.password = password
        self.register_date = register_date
        self.last_pass_change = last_pass_change
        self.account_type = account_type
        self.store = store

    def update_password(self, password):
        self.password = password
        self.last_pass_change = datetime.now()
        self.save()

    def save(self):
        self.store.update('user',
                          {'salt': self.salt,
                           'password': self.password,
                           'register_date': self.register_date,
                           'last_pass_change': self.last_pass_change,
                           'account_type': self.account_type},
                          {'username': self.username})

    @staticmethod
    def load(username, store):
        result = store.read('user',
                            ['username',
                             'salt',
                             'password',
                             'register_date',
                             'last_pass_change',
                             'account_type',
                             'store'],
                            {'username': username})
        return User(*result)

    @staticmethod
    def new(username, salt, password, account_type, store):
        if store.find('user', ['username'], {'username': username})[0] > 0:
            raise Exception("user already exists")

        now = datetime.now()
        store.create('user',
                     {'username': username,
                      'salt': salt,
                      'password': password,
                      'register_date': now,
                      'last_pass_change': now,
                      'account_type': account_type})

    @staticmethod
    def delete(username, store):
        store.delete('user', {'username': username})
