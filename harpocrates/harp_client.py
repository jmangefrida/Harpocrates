from client import net
from enc import KeyKeeper
from cryptography.hazmat.primitives import hashes, serialization
from getpass import getpass

HOST, PORT = "localhost", 9999

private_key, public_key = KeyKeeper.generate_key_pair()

client = net.NetClient(HOST, PORT)

client.connect()
# client.authenticate()

# encoded_key = 
result = client.register_image("testimg", "testrole", "testadmin", "password", public_key)
if result is True:
    print("success")
    with open("priv_key.pem", 'w') as key_file:
        key_file.write(private_key.decode())
    with open("pub_key.pem", 'w') as key_file:
        key_file.write(public_key.decode())
else:
    print("fail")

client.close()
