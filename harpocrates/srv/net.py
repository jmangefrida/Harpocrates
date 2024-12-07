'''
net.py
'''

import socket
import threading
import socketserver
from enc import SecureComm


class TCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls
        print("starting handshake")
        self.hand_shake()

        while True:
            # msg = self.rfile.readline().strip()
            msg = self.request.recv(1024).strip()
            if msg == b'':
                return
            # print(msg)
            self.data = self.sec_com.decrypt(msg)
            print("{} wrote:".format(self.client_address[0]))
            print(self.data)
            # Likewise, self.wfile is a file-like object used to write back
            # to the client
            # self.wfile.write(self.sec_com.encrypt(self.data.upper()))
            self.request.sendall(self.sec_com.encrypt(self.data.upper()))

    def hand_shake(self):
        """
        Client and server need to do a secure handshake before exchanging information
        Server recieves client key
        Server sends it's public key
        Server generates handshake data (salt)
        Both sides generate shared key and finish handshake
        """
        self.sec_com = SecureComm()
        # Read client key
        self.data = self.request.recv(56)
        # Instantiate securecomm object
        self.sec_com.rec_key(self.data)
        # Send client our public key
        self.request.sendall(self.sec_com.send_key())
        # Send salt
        self.data = self.sec_com.generate_handshake_data()
        self.request.sendall(self.data)
        # finish handshake
        self.sec_com.generate_shared_key()
        print('handshake done')

    def authenticate(self):
        pass


class ThreadServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, ip_port) -> None:
        super(ThreadServer, self).__init__(ip_port, TCPHandler)


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
