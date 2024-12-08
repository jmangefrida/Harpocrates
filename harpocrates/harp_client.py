from client import net
from enc import KeyKeeper
from cryptography.hazmat.primitives import hashes, serialization

HOST, PORT = "localhost", 9999

private_key, public_key = KeyKeeper.generate_key_pair()

client = net.NetClient(HOST, PORT)

client.connect()
client.authenticate()

# encoded_key = 
client.register_image("admin", "123", public_key)
client.close()