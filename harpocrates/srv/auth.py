'''
auth.py
'''

from srv.store import Store


class Secret(object):
    """docstring for Secret"""
    def __init__(self, name, account_name, secret, description, store):
        super(Secret, self).__init__()
        self.name = name
        self.account_name = account_name
        self.secret = secret
        self.description = description
        self.store = store

    def save(self):
        self.store.update('secret',
                          {'account_name': self.account_name,
                           'secret': self.secret,
                           'description': self.description},
                          {'name': self.name})

    def delete(self):
        return self.store.delete('secret', {'name': self.name})
        
    @staticmethod
    def load(name, store):
        result = store.read('secret', ['name', 'account_name', 'secret', 'description'], {'name': name})

        return Secret(*result)

    @staticmethod
    def new(name, account_name, secret, description, store):
        try:
            store.create('secret',
                         {'name': name,
                          'account_name': account_name,
                          'secret': secret,
                          'description': description})
            return Secret(name, account_name, secret, description, store)

        except:
            return None


class Client(object):
    """docstring for Client"""
    def __init__(self, name, ip_address, role, public_key):
        super(Client, self).__init__()
        self.name = name
        self.ip_address = ip_address
        self.role = role
        self.public_key = public_key

    @staticmethod
    def load(name, store):
       
        result = store.read('client', ['name', 'ip_address', 'role', 'public_key'], {'name': name})
        if len(result) > 0:
            return Client(*result)
        else:
            return None


class Role(object):
    """docstring for GateKeeper"""
    def __init__(self):
        super(Role, self).__init__()
        self.store = Store()

    def request(self, client, secret_name):
        '''
        A client has requested a secret, we have check to make sure they are allowed
        to have it.  If so provide it, otherwise deny request
        '''

        role = self.store.read('client', ['role'], {'name': client})

        grants = self.store.read('role_assignment', ['count(id)'], {'role_name': role, 'secret_name': secret_name})

        if grants == 0:
            return False
        else:
            return True

    def grant(self, role_name, secret_name):

        self.store.create('role_grant', {'role_name': role_name, 'secret_name': secret_name})

        return True

    def revoke(self, role_name, secret_name):

        self.store.delete('role_grant', {'role_name': role_name, 'secret_name': secret_name})
