"""
enc.py
"""
import base64
import os
import secrets
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.backends.openssl import backend
from cryptography.exceptions import InternalError


class KeyKeeper(object):
    """docstring for KeyKeeper"""
    def __init__(self, store, user=None):
        super(KeyKeeper, self).__init__()
        self.store = store
        self._new_key = None
        self._key = None
        self.fips = self.enable_fips()
        if user is not None:
            self._load_primary_key(user)

        # self.fips = fips.is_fips_mode_enabled

    def _load_primary_key(self, user):
        # key = self.store.read('setting', ['enc_key'], {1: 1})[0]
        pass


    def enable_fips(self):
        try:
            backend._enable_fips()
            return True
        except InternalError:
            return False

    def first_run_key(self):
        """
        Should only be run for the first setup
        """
        self._generate_primary_key()
        # return self.update_user_pass(password)

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

    def unlock_primary_key(self, password, salt, enc_key):
        key = KeyKeeper.hash_pass(password, salt)
        f = Fernet(key)
        self._key = f.decrypt(enc_key)

    def update_user_pass(self, password):
        """
        When passwords are changed, we need to re-encrypt the system key
        using the users hashed password as key and treating system key as token
        """

        token = self._new_key or self._key
        salt = os.urandom(16)
        user_key = KeyKeeper.hash_pass(password, salt)
        f = Fernet(user_key)

        return f.encrypt(token), salt

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

    def check_pass(self, password, salt, enc_key):
        pass

    @staticmethod
    def hash_pass(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000)

        token = kdf.derive(bytes(password, 'UTF-8'))
        key = base64.urlsafe_b64encode(token)

        return key

    @staticmethod
    def generate_key_pair():
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
        # public_bytes = public_key.public_bytes(
        #    encoding=serialization.Encoding.Raw,
        #    format=serialization.PublicFormat.Raw)

        return private_pem, public_pem

    @staticmethod
    def encrypt_with_client_key(data, client_pem):
        public_key = serialization.load_pem_public_key(client_pem, None)
        cipher_text = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )

        return cipher_text


class SecureComm(object):

    def __init__(self, sock) -> None:
        self.private_key = X448PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.peer_public_key = None
        self.info = b'Harpocates'
        self.sock = sock

    def send_key(self):
        pub_key = self.public_key.public_bytes_raw()
        self.public_key = X448PublicKey.from_public_bytes(pub_key)
        # self.public_key.from_public_bytes(pub_key)
        self.sock.sendall(pub_key)
        # return pub_key

    def rec_key(self, ):
        peer_key = self.sock.recv(56)

        self.peer_public_key = X448PublicKey.from_public_bytes(peer_key)

    def send_salt_data(self):
        # self.peer_public_key = peer_public_key
        self.salt = secrets.token_urlsafe(32)
        
        self.sock.sendall(self.salt.encode())
        # self.peer_public_key.encrypt(token)

    def generate_shared_key(self):
        if self.peer_public_key is None:
            raise Exception("No peer key")
        shared_key = self.private_key.exchange(self.peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt.encode(),
            info=self.info,
            ).derive(shared_key)

        self.f = Fernet(base64.urlsafe_b64encode(derived_key))

    def encrypt(self, data):
        return self.f.encrypt(data)

    def sendall(self, data):
        data = self.encrypt(data)
        data = base64.urlsafe_b64encode(data)
        # print(len(data))
        self.sock.sendall(data)

    def decrypt(self, data):
        return self.f.decrypt(data)

    def recv(self, buffer):
        data = self.sock.recv(buffer).strip()
        # print(len(data))
        data = base64.urlsafe_b64decode(data)
        if data == b'':
            return b''
        return self.decrypt(data)

