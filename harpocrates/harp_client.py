from cryptography.hazmat import primitives
from client import net
from enc import KeyKeeper
from cryptography.hazmat.primitives import hashes, serialization
from getpass import getpass
import sys


def register_image(host, port):

    private_key, public_key = KeyKeeper.generate_key_pair()

    client = net.NetClient(host, port)
    client.connect()
    result = client.register_image("testimg", "testrole", "admin", "qaz", public_key)

    if result is True:
        print("success")
        with open("priv_key.pem", 'w') as key_file:
            key_file.write(private_key.decode())
        with open("pub_key.pem", 'w') as key_file:
            key_file.write(public_key.decode())
    else:
        print("fail")
    
    client.close()


def register_client(host, port):

    with open("priv_key.pem", "r") as key_file:
        img_private_key = key_file.read()
        img_private_key = img_private_key.encode()

    private_key, public_key = KeyKeeper.generate_key_pair()

    client = net.NetClient(host, port)
    client.connect()
    result = client.register_client("testimg", img_private_key, public_key)

    if result is True:
        with open("priv_key.pem", 'w') as key_file:
            key_file.write(private_key.decode())
        with open("pub_key.pem", "w") as key_file:
            key_file.write(public_key.decode())
        print("Successfully registed client")
    else:
        print("Failed to register client")

    client.close()


def request_secret(host, port, secret_name):
    with open("priv_key.pem", 'r') as key_file:
        private_key = key_file.read()
        private_key = private_key.encode()

    client = net.NetClient(host, port)
    client.connect()
    account_name, account_secret = client.request_secret("testclient", secret_name, private_key)
    account_password = KeyKeeper.decrypt_with_client_key(account_secret, private_key)
    print(account_name)
    print(len(account_secret))
    print(account_password)
    print("success")


if __name__ == "__main__":

    HOST, PORT = "localhost", 9999

    if sys.argv[1] == "register_image":
        register_image(HOST, PORT)
    elif sys.argv[1] == "register_client":
        register_client(HOST, PORT)
    elif sys.argv[1] == "request_secret":
        request_secret(HOST, PORT, sys.argv[2])
