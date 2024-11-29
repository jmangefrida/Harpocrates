"""
enc.py
"""
import base64
import os
import secrets
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives import fips


class KeyKeeper(object):
    """docstring for KeyKeeper"""
    def __init__(self):
        super(KeyKeeper, self).__init__()
        self._new_key = None
        # self.fips = fips.is_fips_mode_enabled

    def first_run_key(self, password):
        """
        Should only be run for the first setup
        """
        self._generate_primary_key()
        return self.update_user_pass(password)

    def re_encrypt_secret(self, secret):
        """
        When primary key changes, all secrets must be re-encrypted
        """
        if self._new_key:
            f = MultiFernet([self._new_key, self._key])
            return f.rotate(secret)
        else:
            raise Exception("No new key to rotate with")

    def rotate_primary_key(self):
        '''
        Key cannot just be changed.  It needs to rencrypt all the secrets and users passwords
        '''
        self._new_key = self._generate_primary_key()
        self.generation = self.generation + 1

    def _generate_primary_key(self):

        self._key = Fernet.generate_key()

    def _hash_pass(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000)

        token = kdf.derive(bytes(password, 'UTF-8'))
        key = base64.urlsafe_b64encode(token)

        return key

    def unlock_primary_key(self, password, salt, enc_key):
        key = self._hash_pass(password, salt)
        f = Fernet(key)
        self._key = f.decrypt(enc_key)

    def update_user_pass(self, password):
        """
        When passwords are changed, we need to re-encrypt the key
        viceversa as well.  Make sure to use newest generation of key
        """

        key = self._new_key or self._key
        salt = os.urandom(16)
        key = self._hash_pass(password, salt)
        f = Fernet(key)

        return f.encrypt(key), salt

    def encrypt_secret(self, secret):
        f = Fernet(self._key)
        return f.encrypt(secret)
