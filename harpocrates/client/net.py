"""
client/net.py
"""

from enc import KeyKeeper, SecureComm
import socket
import base64



class NetClient():
    def __init__(self, ip, port) -> None:
        self.ip = ip
        self.port = port

    def connect(self):
        """
        Does a two-way handshake with the server, exchanging keys
        and making a shared key using X448
        """

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.ip, self.port))
        # print("connected")
        self.sec_com = SecureComm(self.sock)
        # print("sending key")
        #self.sock.sendall(self.sec_com.send_key())
        self.sec_com.send_key()
        # print("recieving key")
        #rec_key = self.sock.recv(56)
        # rec_key = rec_key.splitlines()[0]
        # print(rec_key)
        self.sec_com.rec_key()
        # print("recieving salt")
        self.sec_com.salt = self.sock.recv(1024).strip().decode()
        # print(sec_com.salt)
        # print("generating key")
        self.sec_com.generate_shared_key()
        # print("sending message")
        self.sec_com.sendall("hi".encode())
        msg = self.sec_com.recv()
        print(msg.decode())

    def authenticate(self,):
        self.sec_com.sendall("AUTHENTICATE".encode())

    def register_image(self, img_name, role_name, user, password, pub_key):

        self.sec_com.sendall("REGISTER_IMG".encode())
        print(self.sec_com.recv().decode())
        self.sec_com.sendall(img_name.encode())
        print(self.sec_com.recv().decode())
        self.sec_com.sendall(role_name.encode())
        print(self.sec_com.recv().decode())
        self.sec_com.sendall(user.encode())
        print(self.sec_com.recv().decode())
        # print('sent' + user)
        # self.sec_com.recv(1024)
        self.sec_com.sendall(password.encode())
        print('sent' + "password")
        print(self.sec_com.recv().decode())
        # pub_key = base64.urlsafe_b64encode(pub_key)
        self.sec_com.sendall(pub_key)
        print('sent key')
        result = self.sec_com.recv().decode()
        if result == "OK4":
            return True
        else:
            return False
        print(self.sec_com.recv().decode())

    def register_client(self, client_name, img_name, img_private_key, pub_key):

        self.sec_com.sendall("REGISTER_CLIENT".encode())
        print(self.sec_com.recv().decode())
        self.sec_com.sendall(client_name.encode())
        # print(self.sec_com.recv().decode())
        self.sec_com.sendall(img_name.encode())
        token = self.sec_com.recv()
        data = KeyKeeper.decrypt_with_client_key(token, img_private_key)
        self.sec_com.sendall(data)
        result = self.sec_com.recv().decode()
        if result == "OK":
            self.sec_com.sendall(pub_key)
        else:
            return False
        result = self.sec_com.recv().decode()
        if result == "OK":
            return True
        else:
            print(result)
            return False

    def request_secret(self, client_name, secret_name, private_key):
        self.sec_com.sendall("REQUEST_SECRET".encode())
        print(self.sec_com.recv().decode())
        self.sec_com.sendall(client_name.encode())
        token = self.sec_com.recv()
        data = KeyKeeper.decrypt_with_client_key(token, private_key)
        self.sec_com.sendall(data)
        result = self.sec_com.recv().decode()
        print(result)
        if result == "OK":
            self.sec_com.sendall(secret_name.encode())
            account_name = self.sec_com.recv().decode()
            print(account_name)
            account_secret = self.sec_com.recv()
            print(account_secret)
            return account_name, account_secret

        else:
            return False

    def close(self):
        self.sec_com.sendall(b'')


if __name__ == "__main__":
    while True:
        msg = input("msg:")
        if msg == "end":
            exit
        msg = sec_com.encrypt(msg)
        # print(msg)
        sock.sendall(msg)
        msg = sock.recv(1024) 
        print(sec_com.decrypt(msg))
