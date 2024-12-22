from srv.net import ThreadServer
from srv.user import User
from srv.store import Store
from srv.cmd import Cmd
import threading
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
import enc
import socket


class Main():
    HOST, PORT = "localhost", 9999
    HOSTNAME = socket.gethostname()
    IP_ADDRESS = socket.gethostbyname(HOSTNAME)
    VERSION = "0.1"

    def __init__(self,):
        
        self.store = Store()
        self.net_srv = None
        self.status = "stopped"
        #password = input("password:")

    def unlock(self, username, password):
        try:
            user = User.load(username, self.store)
            # print(user)
            key = enc.KeyKeeper.decrypt_system_key(password, user.salt, user.enc_key)
            self.keeper = enc.KeyKeeper(self.store, key)
        except InvalidToken:
            print("Password Incorrect!")
            return False
        except TypeError:
            key = enc.KeyKeeper._generate_primary_key()
            self.keeper = enc.KeyKeeper(self.store, key)
            salt, enc_key = self.keeper.update_user_pass(password)
            user = User.new('testadmin', salt, enc_key, 'admin', self.store)
        
        # print("system key:")
        # print(key)
        
        # user.salt, user.enc_key = self.keeper.update_user_pass('password')
        # user.save()
        # self.keeper.first_run_key()
        self.start()

        return True

    def start(self):
        self.cmd = Cmd(self.keeper, self.store)
        # self.cmd.keeper.first_run_key()
        try:
            if self.status == 'stopped':
                self.net_srv = ThreadServer((Main.HOST, Main.PORT), self.cmd)
                self.net_srv.allow_reuse_address = True

            self.counter = 0
            self.server_thread = threading.Thread(target=self.net_srv.serve_forever)
            self.server_thread.daemon = False
            self.server_thread.start()
            self.status = "started"
            return True
        except OSError:
            return False

    def stop(self):
        self.net_srv.shutdown()
        self.server_thread.join()

        #self.net_srv = None
        del self.server_thread
        del self.net_srv
        self.status = "stopped"

    def test_run(self):
        unlocked = False
        
        while unlocked is False:
            # user = input("Username:")
            user = "testadmin"
            # password = input("Password:")
            password = "password"
            unlocked = self.unlock(user, password)
        # self.cmd.create_secret('test_secret', 'user', 'password', 'This is a test account')
        # self.cmd.grant('testrole', 'test_secret')

        ip, port = self.net_srv.server_address
        server_thread = threading.Thread(target=self.net_srv.serve_forever)
        server_thread.daemon = False
        server_thread.start()
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        print("server running")
        input("")
        print("shuting down")
        self.net_srv.shutdown()