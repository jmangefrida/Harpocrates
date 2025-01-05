'''
net.py
'''

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
        self.request.settimeout(10)
        self.server.cmd.counter += 1
        self.hand_shake()

        msg = ''
        while True:
            try:
                msg = self.sec_com.recv()
                if msg is False:
                    return
            except (ConnectionResetError, AttributeError):
                return

            msg = msg.decode()
            if msg == "REGISTER_IMG":
                self.register_img()
                return
            elif msg == "REGISTER_CLIENT":
                self. register_client()
                return
            elif msg == "REQUEST_SECRET":
                self.request_secret()
                return
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
        # Instantiate securecomm object
        self.sec_com.rec_key()
        # Send client our public key
        self.sec_com.send_key()
        # Send salt
        self.sec_com.send_salt_data()
        # finish handshake
        self.sec_com.generate_shared_key()
        print('handshake done')

    def cmd(self):
        pass

    def authenticate(self):
        pass

    def register_img(self):
        self.sec_com.sendall(b'OK1')
        img_name = self.sec_com.recv().decode()
        self.sec_com.sendall(b'OK1')
        role_name = self.sec_com.recv().decode()
        self.sec_com.sendall(b'OK1')
        username = self.sec_com.recv().decode()
        self.sec_com.sendall(b'OK2')
        password = self.sec_com.recv().decode()
        self.sec_com.sendall(b'OK3')
        pub_key = self.sec_com.recv().decode()
        r = self.server.cmd.register_img(subject=username,
                                         access_point=self.client_address[0],
                                         object=img_name,
                                         role=role_name,
                                         password=password,
                                         pub_key=pub_key)[0]
        if r is not False:
            self.sec_com.sendall(b'OK4')
        else:
            self.sec_com.sendall(b'FAIL')

    def register_client(self):
        self.sec_com.sendall(b'OK1')
        client_name = self.sec_com.recv().decode()
        img_name = self.sec_com.recv().decode()
        img = self.server.cmd.get_image(img_name)[0]
        data = img.start_authenticate()
        cipher = self.server.cmd.get_cypher(data, img.public_key)
        #cipher, img = self.server.cmd.auth_img(img_name)
        self.sec_com.sendall(cipher)
        data = self.sec_com.recv()
        #if data == img.data:
        auth = self.server.cmd.auth_img(subject=client_name, 
                                        access_point=self.client_address[0], 
                                        object=img_name, data=data, 
                                        img_data=img.data)[0]
        if auth is True:
            self.sec_com.sendall(b'OK')
            pub_key = self.sec_com.recv().decode()
            r = self.server.cmd.register_client(subject=client_name,
                                                access_point=self.client_address[0],
                                                object=img_name,
                                                pub_key=pub_key)[0]
            if r is True:
                self.sec_com.sendall(b'OK')
            else:
                self.sec_com.sendall(b'FAIL_REGISTER')
        else:
            self.sec_com.sendall(b'FAIL_DECRYPT')

    def request_secret(self):
        self.sec_com.sendall(b'OK1')
        client_name = self.sec_com.recv().decode()
        client = self.server.cmd.get_client(client_name)[0]
        if client is None:
            self.sec_com.sendall(b'FAIL')
            return
        data = client.start_authenticate()
        cipher = self.server.cmd.get_cypher(data, client.public_key)
        #cipher, client = self.server.cmd.auth_client(client_name, self.client_address[0])[1]
        
        self.sec_com.sendall(cipher)
        rcv_data = self.sec_com.recv()
        auth =  self.server.cmd.auth_client(subject=client_name,
                                        access_point=self.client_address[0],
                                        object='',
                                        rcv_data=rcv_data,
                                        client_data=data)[0]
        if auth is True:
        #if data == client.data:
            self.sec_com.sendall(b'OK')
            secret_name = self.sec_com.recv().decode()
            secret = self.server.cmd.request_secret(secret_name, client)
            self.sec_com.sendall(secret.account_name.encode())
            self.sec_com.sendall(secret.prepared_secret)
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
