'''
cmd.py
'''
# import secrets
from cryptography.fernet import InvalidToken
# from srv.store import Store
from srv.user import User
from enc import KeyKeeper
from srv.auth import Secret, Client, Role, Image
from datetime import datetime
import srv.log_event as log


class Cmd(object):
    """docstring for Cmd"""

    def __init__(self, keeper, main):
        self.main = main
        self.counter = 0
        self.keeper: KeyKeeper = keeper

    @log.log_event
    def register_img(self, subject, access_point, object, role, password, pub_key):
        # subject = username, object = image name
        try:
            user = User.load(subject)
            self.keeper.check_pass(password, user.salt, user.enc_key)
            
            # If the pre_register setting is on, we need to make sure the image
            # already exists
            if self.main.settings['pre_register'] == 'on':
                image = Image.load(object)
            role = Role.load(role)
        except (InvalidToken, ValueError) as e:
            print("error:" + e.__str__())
            return (False, )
        self.save_img(subject=subject, access_point=access_point, object=object, role_name=role.name, pub_key=pub_key)
        return (True,) 

    @log.log_event
    def save_img(self, subject, access_point, object, role_name, pub_key):

        Image.new(object, datetime.now(), subject, role_name, pub_key)
        print("image registered")
        return (True,)

    def get_image(self, img_name):
        return (True, Image.load(img_name))

    def get_client(self, client_name):
        return (True, Client.load(client_name))

    def get_cypher(self, data, key):
        return (True,  KeyKeeper.encrypt_with_client_key(data, key))

    @log.log_event
    def auth_img(self, subject, access_point, object, client_data, img_data):
        if client_data == img_data:
            return (True, )
        else:
            return (False, )

    @log.log_event
    def auth_client(self, subject, access_point, object, rcv_data, client_data):
        if rcv_data == client_data:
            return (True, )
        else:
            return (False, )

    @log.log_event
    def register_client(self, client_name, client_ip, img_name, pub_key):
        Client.new(client_name, client_ip, img_name, pub_key)

        return (True, )

    @log.log_event
    def request_secret(self, secret_name, client):
        img = Image.load(client.image_name)
        role = Role.load(img.role)
        secret = role.request(secret_name)
        secret.prepared_secret = self.keeper.prepare_secret(secret.secret, client.public_key)
        
        return (True, secret)

    @log.log_event
    def create_secret(self, account_name, account_pass, description, subject, access_point, object):
        account_secret = self.keeper.encrypt_secret(account_pass)
        Secret.new(object, account_name, account_secret, description)
        
        return (True,)
    
    @log.log_event
    def create_role(self, description, subject, access_point, object):
        Role.new(object, description)
        
        return (True,)

    @log.log_event
    def create_image(self, role_name, description, subject, access_point, object):
        Image.new(object, None, subject, role_name, None)
        
        return (True,)

    @log.log_event
    def create_user(self, password, subject, access_point, object):
        salt, enc_key = self.keeper.update_user_pass(password)
        User.new(object, salt, enc_key, 'admin')
        
        return (True,)

    @log.log_event
    def create_grant(self, role_name, subject, access_point, object):
        secret = Secret.load(object)
        role = Role.load(role_name)
        role.grant(secret.name)
        
        return (True, )

    @log.log_event
    def delete_secret(self, subject, access_point, object):
        Secret.delete(object)

        return (True, )

    @log.log_event
    def delete_role(self, subject, access_point, object):
        Role.delete(object)
        
        return (True,)

    @log.log_event
    def delete_image(self, subject, access_point, object):
        Image.delete(object)
        
        return (True, )

    @log.log_event
    def delete_client(self, subject, access_point, object):
        Client.delete(object)
        
        return (True, )

    @log.log_event
    def delete_user(self, subject, access_point, object):
        User.delete(object)
        
        return (True, )

    @log.log_event
    def delete_grant(self, role_name, subject, access_point, object):
        role = Role.load(role_name)
        role.delete_grant(object)

        return (True, )

    def list_secrets(self):
        secrets = Secret.find(None)
        
        return secrets

    def list_clients(self):
        results = Client.find(None)
        
        return results

    def list_images(self):
        results = Image.find(None)
        
        return results

    def list_roles(self):
        results = Role.find(None)
        
        return results

    def list_users(self):
        results = User.find(None)
        
        return results

    def list_grants(self, role_name):
        #results = Role.find_grants(None)
        role = Role.load(role_name)
        return role.get_grants()
