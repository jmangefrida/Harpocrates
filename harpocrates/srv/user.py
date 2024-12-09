'''
user.py
'''
from os import access, stat
from datetime import datetime


class User():

    def __init__(self,
                 username,
                 salt,
                 enc_key,
                 register_date,
                 last_pass_change,
                 account_type,
                 store):
        self.username = username
        self.salt = salt
        self.enc_key = enc_key
        self.register_date = register_date
        self.last_pass_change = last_pass_change
        self.account_type = account_type
        self.store = store
        self.key = None

    def update_password(self, password):
        self.password = password
        self.last_pass_change = datetime.now()
        self.save()

    def save(self):
        self.store.update('user',
                          {'salt': self.salt,
                           'enc_key': self.enc_key,
                           'register_date': self.register_date,
                           'last_pass_change': self.last_pass_change,
                           'account_type': self.account_type},
                          {'username': self.username})

    @staticmethod
    def load(username, store):
        result = store.read('user',
                            ['username',
                             'salt',
                             'enc_key',
                             'register_date',
                             'last_pass_change',
                             'account_type'],
                            {'username': username})
        print(result)
        return User(*result)

    @staticmethod
    def new(username, salt, enc_key, account_type, store):
        if len(store.find('user', ['username'], {'username': username})) > 0:
            raise Exception("user already exists")

        now = datetime.now()
        store.create('user',
                     {'username': username,
                      'salt': salt,
                      'enc_key': enc_key,
                      'register_date': now,
                      'last_pass_change': now,
                      'account_type': account_type})
        # store.cur.execute('commit')

        return User(username, salt, enc_key, now, now, account_type, store)

    @staticmethod
    def delete(username, store):
        store.delete('user', {'username': username})
