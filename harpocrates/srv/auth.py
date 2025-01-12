'''
auth.py
'''
import os
import srv.store

store = srv.store.store


class Secret(object):
    """docstring for Secret"""
    def __init__(self, name, account_name, secret, description):
        super(Secret, self).__init__()
        self.name = name
        self.account_name = account_name
        self.secret = secret
        self.description = description
        self.prepared_secret = b''

    def save(self):
        store.update('secret',
                     {'account_name': self.account_name,
                      'secret': self.secret,
                      'description': self.description},
                     {'name': self.name})

    @staticmethod
    def delete(name):
        return store.delete('secret', {'name': name})        

    @staticmethod
    def load(name):
        result = store.read('secret', 
                            ['name', 'account_name', 'secret', 'description'], 
                            {'name': name})

        if result is not None:
            return Secret(*result)
        else:
            raise ValueError("Secret does not exist")

    @staticmethod
    def new(name, account_name, secret, description):
        try:
            store.create('secret',
                         {'name': name,
                          'account_name': account_name,
                          'secret': secret,
                          'description': description})
            return Secret.load(name)

        except:
            return None

    @staticmethod
    def find(filters):
        if filters is None:
            filters = {}
        results = store.find('secret', ['name', 'description'], filters)
        return results


class Client(object):
    """docstring for Client"""
    def __init__(self, name, ip_address, image_name, public_key):
        super(Client, self).__init__()
        self.name = name
        self.ip_address = ip_address
        self.image_name = image_name
        self.public_key = public_key

    def start_authenticate(self):
        self.data = os.urandom(32)
        return self.data

    def save(self):
        store.update('client',
                     {'ip_address', self.ip_address,
                      'role', self.role,
                      'public_key', self.public_key},
                     {'name': self.name})

    @staticmethod
    def load(name):
       
        result = store.read('client', 
                            ['name', 'ip_address', 'image_name', 'public_key'], 
                            {'name': name})
        if result is not None:
            result = list(result)
            result.append(store)
            return Client(*result)
        else:
            raise ValueError("Client does not exist")

    @staticmethod
    def new(name, ip_address, image_name, public_key):
        store.create('client', 
                     {'name': name,
                      'ip_address': ip_address,
                      'image_name': image_name, 
                      'public_key': public_key})
        return Client.load(name)

    @staticmethod
    def delete(name):
        store.delete('client', {'name': name})

    @staticmethod
    def find(filters):
        if filters is None:
            filters = {}
        results = store.find('client', ['name', 'image_name', 'ip_address'], filters)
        return results


class Role(object):
    """docstring for GateKeeper"""
    def __init__(self, name, description):
        super(Role, self).__init__()
        self.name = name
        self.description = description

    def request(self, secret_name):
        '''
        A client has requested a secret, we have check to make sure they are allowed
        to have it.  If so provide it, otherwise deny request
        '''

        grants = store.read('role_grant', 
                            ['count(id)'], 
                            {'role_name': self.name, 'secret_name': secret_name})

        if grants[0] == 1:
            return Secret.load(secret_name)
        else:
            raise Exception("Not Authorized")

    def grant(self, secret_name):

        store.create('role_grant', {'role_name': self.name, 'secret_name': secret_name})

        return True

    def get_grants(self):

        results = store.find('role_grant', ['secret_name'], {'role_name': self.name})
        return [x[0] for x in results]

    def delete_grant(self, secret_name):
        store.delete('role_grant', {'role_name': self.name, 'secret_name': secret_name})

    def revoke(self, role_name, secret_name):

        store.delete('role_grant', {'role_name': role_name, 'secret_name': secret_name})

    @staticmethod
    def load(name):
        result = store.read('role', ['name', 'description'], {'name': name})
        if result is not None:
            return Role(*result)
        else:
            raise ValueError("Role does not exist")

    @staticmethod
    def new(name, description):
        store.create('role', {'name': name, 'description': description})
        return Role.load(name)

    @staticmethod
    def delete(name):
        store.delete('role_grant', {'role_name': name})
        store.delete('role', {'name': name})

    @staticmethod
    def find(filters):
        if filters is None:
            filters = {}
        results = store.find('role', ['name', 'description'], filters)
        return results

    @staticmethod
    def find_grants(filters):
        if filters is None:
            filters = {}
        results = store.find('role_grant', ['id', 'role_name', 'secret_name'], filters)
        return results


class Image():
    def __init__(self, name, date_registered, registerd_by, role, public_key) -> None:
        self.name = name
        self.date_registered = date_registered
        self.registerd_by = registerd_by
        self.role = role
        self.public_key = public_key
 
    def save(self):
        store.update('image',
                     {'date_registered': self.date_registered,
                      'registerd_by': self.registerd_by,
                      'role': self.role,
                      'public_key': self.public_key},
                     {'name': self.name})

    def start_authenticate(self):
        self.data = os.urandom(32)
        return self.data

    @staticmethod
    def load(name):
        result = store.read('image',
                            ['name', 'date_registered', 'registered_by', 'role', 'public_key'],
                            {'name': name})
        if result is not None:
            
            return Image(*result)
        else:
            raise ValueError("Image does not exist")

    @staticmethod
    def new(name, date_registered, registered_by, role, public_key):

        if date_registered is None:
            date_registered = 'now()'
        if public_key is None:
            public_key = ''

        store.create('image',
                     {'name': name,
                      'date_registered': date_registered,
                      'registered_by': registered_by,
                      'role': role,
                      'public_key': public_key})
        return Image.load(name)

    @staticmethod
    def delete(name):
        store.delete('image', {'name': name})

    @staticmethod
    def find(filters):
        if filters is None:
            filters = {}
        results = store.find('image', ['name', 'role', 'registered_by'], filters)
        return results
