'''
user.py
'''
# from os import access, stat
from datetime import datetime
# from enc import KeyKeeper
import srv.store

store = srv.store.store


class User():

    def __init__(self,
                 username,
                 salt,
                 enc_key,
                 register_date,
                 last_pass_change,
                 account_type):
        self.username = username
        self.salt = salt
        self.enc_key = enc_key
        self.register_date = register_date
        self.last_pass_change = last_pass_change
        self.account_type = account_type
        self.key = None

    def update_password(self, password):
        self.password = password
        self.last_pass_change = datetime.now()
        self.save()

    def authenticate(self, salt, password):
        pass

    def save(self):
        print('saving :')
        # print(self.salt)

        store.update('user',
                     {'salt': self.salt,
                      'enc_key': self.enc_key,
                      'register_date': self.register_date,
                      'last_pass_change': self.last_pass_change,
                      'account_type': self.account_type},
                     {'username': self.username})

    @staticmethod
    def load(username):
        result = store.read('user',
                            ['username',
                             'salt',
                             'enc_key',
                             'register_date',
                             'last_pass_change',
                             'account_type'],
                            {'username': username})
        
        if result is not None:
            return User(*result)
        else:
            raise ValueError("User does not exist")

    @staticmethod
    def new(username, salt, enc_key, account_type):
        now = datetime.now()
        print('creating')
        print(enc_key)
        store.create('user',
                     {'username': username,
                      'salt': salt,
                      'enc_key': enc_key,
                      'register_date': now,
                      'last_pass_change': now,
                      'account_type': account_type})
        # store.cur.execute('commit')

        return User(username, salt, enc_key, now, now, account_type)

    @staticmethod
    def delete(username):
        store.delete('user', {'username': username})

    @staticmethod
    def find(filters):
        if filters is None:
            filters = {}
        results = store.find('user', ['username', 'account_type'], filters)
        return results
