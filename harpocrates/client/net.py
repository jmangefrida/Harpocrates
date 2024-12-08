"""
client/net.py
"""

from enc import KeyKeeper, SecureComm
import socket


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
        msg = self.sec_com.recv(1024)
        print(msg.decode())

    def authenticate(self,):
        self.sec_com.sendall("AUTHENTICATE".encode())

    def register_client(self):
        self.sec_com.sendall("REGISTER".encode())

    def register_image(self, user, password, pub_key):

        self.sec_com.sendall("REGISTER_IMG".encode())
        self.sec_com.recv(1024)
        self.sec_com.sendall(b'user' + user.encode())
        self.sec_com.recv(1024)
        print('sent' + user)
        self.sec_com.recv(1024)
        self.sec_com.sendall(password.encode())
        self.sec_com.recv(1024)
        self.sec_com.sendall(pub_key)

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
