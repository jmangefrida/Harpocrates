'''
net.py
'''

import re
import socket
import threading
import socketserver
import base64
# from socketserver import _RequestType, _RetAddress, BaseServer
from enc import SecureComm
from srv.user import User
from cmd import Cmd


class TCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    #def __init__(self, *args) -> None:
    #    self.keeper = args[-1]
    #    print(self.keeper)
    #    print(args)
    #    super(TCPHandler).__init__(*args)

    def handle(self):
        self.request.settimeout(10)
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls
        self.server.cmd.counter += 1
        # print("count: " + str(self.server.cmd.counter))
        print("system key:")
        print(self.server.cmd.keeper._key)
        #print(self.server.keeper._key)
        # print("starting handshake")
        self.hand_shake()

        msg = ''
        while True:
            # msg = self.rfile.readline().strip()
            # msg = self.request.recv(1024).strip()
            try:
                msg = self.sec_com.recv()
                if msg is False:
                    return
            except (ConnectionResetError, AttributeError):
                return

            # print(msg)
            # self.data = self.sec_com.decrypt(msg)
            # print("{} wrote:".format(self.client_address[0]))
            msg = msg.decode()
            print(msg)
            if msg == "REGISTER_IMG":
                self.register_img()
                return
            elif msg == "REGISTER_CLIENT":
                self. register_client()
                return
            elif msg == "REQUEST_SECRET":
                self.request_secret()
                return
            # Likewise, self.wfile is a file-like object used to write back
            # to the client
            # self.wfile.write(self.sec_com.encrypt(self.data.upper()))
            # self.request.sendall(self.sec_com.encrypt(self.data.upper()))
            self.sec_com.sendall(msg.upper().encode())


    def hand_shake(self):
        """
        Client and server need to do a secure handshake before exchanging information
        Server recieves client key
        Server sends it's public key
        Server generates handshake data (salt)
        Both sides generate shared key and finish handshake
        """
        self.sec_com = SecureComm(self.request)
        # Read client key
        # self.data = self.request.recv(56)
        # Instantiate securecomm object
        self.sec_com.rec_key()
        # Send client our public key
        # self.request.sendall(self.sec_com.send_key())
        self.sec_com.send_key()
        # Send salt
        self.sec_com.send_salt_data()
        # self.request.sendall(self.data)
        # finish handshake
        self.sec_com.generate_shared_key()
        print('handshake done')

    def cmd(self):
        pass

    def authenticate(self):
        pass

    def register_img(self):
        # try:
            self.sec_com.sendall(b'OK1')
            img_name = self.sec_com.recv().decode()
            self.sec_com.sendall(b'OK1')
            role_name = self.sec_com.recv().decode()
            self.sec_com.sendall(b'OK1')
            username = self.sec_com.recv().decode()
            # print(username)
            self.sec_com.sendall(b'OK2')
            password = self.sec_com.recv().decode()
            # print(password)
            self.sec_com.sendall(b'OK3')
            pub_key = self.sec_com.recv().decode()
            # print(pub_key)
        # except:
            # print("error")
            # return

            # user = User.load(username, self.server.main.store)
            r = self.server.cmd.register_img(img_name, role_name, username, password, pub_key)
            print(r)
            if r is not False:
                self.sec_com.sendall(b'OK4')
            else:
                self.sec_com.sendall(b'FAIL')

            # pub_key = self.sec_com.recv(2048).decode()

    def register_client(self):
        self.sec_com.sendall(b'OK1')
        client_name = self.sec_com.recv().decode()
        img_name = self.sec_com.recv().decode()
        cipher, img = self.server.cmd.auth_img(img_name)
        self.sec_com.sendall(cipher)
        data = self.sec_com.recv()
        if data == img.data:
            self.sec_com.sendall(b'OK')
            pub_key = self.sec_com.recv().decode()
            r = self.server.cmd.register_client(client_name, self.client_address[0], img_name, pub_key)
            if r is True:
                self.sec_com.sendall(b'OK')
            else:
                self.sec_com.sendall(b'FAIL_REGISTER')
        else:
            self.sec_com.sendall(b'FAIL_DECRYPT')

    def request_secret(self):
        self.sec_com.sendall(b'OK1')
        client_name = self.sec_com.recv().decode()
        cipher, client = self.server.cmd.auth_client(client_name)
        self.sec_com.sendall(cipher)
        data = self.sec_com.recv()
        if data == client.data:
            self.sec_com.sendall(b'OK')
            secret_name = self.sec_com.recv().decode()
            secret = self.server.cmd.request_secret(secret_name, client)
            print('sending secret: ' + secret.account_name)
            self.sec_com.sendall(secret.account_name.encode())
            print(secret.prepared_secret)
            print(len(secret.prepared_secret))
            self.sec_com.sendall(secret.prepared_secret)
            print("success")
        else:
            self.sec_com.sendall(b'FAIL')








class ThreadServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def myhandler(self):
        print("handled")

    def __init__(self, ip_port, cmd) -> None:
        super(ThreadServer, self).__init__(ip_port, TCPHandler)
        self.cmd = cmd

    class MyHandler(socketserver.BaseRequestHandler):

        def handle(self):
            print("handle")

            return super().handle()


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    
    # Create the server, binding to localhost on port 9999
    server = ThreadServer((HOST, PORT), TCPHandler)
    
    with server:
        ip, port = server.server_address
    
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = False
        server_thread.start()
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        print("server running")
        input("sdf")
        print("shuting down")
        server.shutdown()
