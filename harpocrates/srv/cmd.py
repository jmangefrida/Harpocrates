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
        self.store = main.store
        self.counter = 0
        self.keeper: KeyKeeper = keeper

    def register_img(self, img_name, role_name,  username, password, pub_key):
        try:
            user = User.load(username, self.store)
            self.keeper.check_pass(password, user.salt, user.enc_key)
            
            # If the pre_register setting is on, we need to make sure the image
            # already exists
            if self.main.settings['pre_register'] == 'on':
                image = Image.load(img_name, self.store)
            role = Role.load(role_name, self.store)
        except InvalidToken as e:
            print("password invalid")
            return False
        self._save_img(img_name, role_name, username, pub_key)
        return True

    @log.log_event
    def _save_img(self, img_name, role_name, username, pub_key):

        Image.new(img_name, datetime.now(), username, role_name, pub_key, self.store)
        print("image registered")
        pass

    def auth_img(self, img_name):
        img = Image.load(img_name, self.store)
        data = img.start_authenticate()
        cipher = KeyKeeper.encrypt_with_client_key(data, img.public_key)
        return cipher, img

    def auth_client(self, client_name, client_ip):
        client = Client.load(client_name, self.store)
        # if restrict_ip is on, check to make sure the client is using the same IP
        if client.ip_address != client_ip:
            return None, None
        data = client.start_authenticate()
        cipher = KeyKeeper.encrypt_with_client_key(data, client.public_key)
        return cipher, client

    def register_client(self, client_name, client_ip, img_name, pub_key):
        Client.new(client_name, client_ip, img_name, pub_key, self.store)
        return True

    def request_secret(self, secret_name, client):
        img = Image.load(client.image_name, self.store)
        role = Role.load(img.role, self.store)
        secret = role.request(secret_name)
        secret.prepared_secret = self.keeper.prepare_secret(secret.secret, client.public_key)
        return secret

    @log.log_event
    def create_secret(self, secret_name, account_name, account_pass, description):
        account_secret = self.keeper.encrypt_secret(account_pass)
        Secret.new(secret_name, account_name, account_secret, description, self.store)
        return True
    
    @log.log_event
    def create_role(self, role_name, description):
        Role.new(role_name, description, self.store)
        return True

    @log.log_event
    def create_image(self, name, role_name, description, user):
        Image.new(name, None, user, role_name, None, self.store)
        return True

    @log.log_event
    def create_user(self, name, password):
        salt, enc_key = self.keeper.update_user_pass(password)
        User.new(name, salt, enc_key, 'admin', self.store)
        return True

    @log.log_event
    def delete_secret(self, name):
        Secret.delete(name, self.store)
        return True

    @log.log_event
    def delete_role(self, name):
        Role.delete(name, self.store)
        return True

    @log.log_event
    def delete_image(self, name):
        Image.delete(name, self.store)
        return True

    @log.log_event
    def delete_client(self, name):
        Client.delete(name, self.store)
        return True

    @log.log_event
    def delete_user(self, name):
        User.delete(name, self.store)
        return True

    @log.log_event
    def grant(self, role_name, secret_name):
        secret = Secret.load(secret_name, self.store)
        role = Role.load(role_name, self.store)
        role.grant(secret.name)
        return True

    def list_secrets(self):
        secrets = Secret.find(None, self.store)
        return secrets

    def list_clients(self):
        results = Client.find(None, self.store)
        return results

    def list_images(self):
        results = Image.find(None, self.store)
        return results

    def list_roles(self):
        results = Role.find(None, self.store)
        return results

    def list_users(self):
        results = User.find(None, self.store)
        return results

   
        
       
