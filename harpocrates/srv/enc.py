"""
enc.py
"""
import base64
import os
# import secrets
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends.openssl import backend
from cryptography.exceptions import InternalError


class KeyKeeper(object):
    """docstring for KeyKeeper"""
    def __init__(self, key):
        super(KeyKeeper, self).__init__()
        self._new_key = None
        self._key = key
        self.fips = self.enable_fips()

        # self.fips = fips.is_fips_mode_enabled

    def enable_fips(self):
        try:
            backend._enable_fips()
            return True
        except InternalError:
            return False

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
        return f.encrypt(bytes(secret, 'utf-8'))

    def prepare_secret(self, secret, client_pem):
        """
        Takes the system encrypted secret, decrypts and re-encrypt
        using the public key of the client it will be sent to.
        """

        # f = MultiFernet([self._new_key, self._key])
        f = Fernet(self._key)
        plain_text = f.decrypt(secret)
        # public_key = serialization.load_pem_public_key(client_pem, None)
        # cipher_text = public_key.encrypt(
        #     plain_text,
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )

        cipher_text = KeyKeeper.encrypt_with_client_key(plain_text, client_pem)
        
        return cipher_text

    def generate_key_pair(self):
        """
        Used when communicating with the client.  Each entity needs to create it's own key pair for
         secure communication.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        return private_pem, public_pem

    @staticmethod
    def encrypt_with_client_key(data, client_pem):
        public_key = serialization.load_der_public_key(client_pem, None)
        cipher_text = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )

        return cipher_text
