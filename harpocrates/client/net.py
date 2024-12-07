"""
client/net.py
"""

from enc import KeyKeeper, SecureComm
import socket


print("it worked")


HOST, PORT = "localhost", 9999
data = "Hellow world"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect((HOST, PORT))
print("connected")
sec_com = SecureComm()
print("sending key")
sock.sendall(sec_com.send_key())
print("recieving key")
rec_key = sock.recv(56)
# rec_key = rec_key.splitlines()[0]
# print(rec_key)
sec_com.rec_key(rec_key)
print("recieving salt")
sec_com.salt = sock.recv(1024).strip().decode()
# print(sec_com.salt)
print("generating key")
sec_com.generate_shared_key()
print("sending message")


while True:
    msg = input("msg:")
    if msg == "end":
        exit
    msg = sec_com.encrypt(msg)
    # print(msg)
    sock.sendall(msg)
    msg = sock.recv(1024) 
    print(sec_com.decrypt(msg))
