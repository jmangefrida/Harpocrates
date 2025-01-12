from srv.net import ThreadServer
from srv.user import User
from srv.store import Store
from srv.cmd import Cmd
import threading
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
import enc
import socket
from srv.log import Log
import srv.store

store = srv.store.store


class Main():
    HOST, PORT = "localhost", 9999
    HOSTNAME = socket.gethostname()
    IP_ADDRESS = socket.gethostbyname(HOSTNAME)
    VERSION = "0.1"

    def __init__(self):
        
        self.net_srv = None
        self.status = "stopped"
        self.settings = {}
        self.load_settings()
        self.log = Log()

    def load_settings(self):
        self.settings = {}
        result = store.find('setting', ['name', 'value'], {})
        for row in result:
            self.settings[row[0]] = row[1]

    def update_settings(self, settings):
        for setting in store.SETTINGS:
            if setting in settings:
                store.update('setting', {'value': settings[setting]}, {'name': setting})
            else:
                store.update('setting', {'value': ''}, {'name': setting})
        self.load_settings()

    def check_for_first_run(self):
        result = store.find('user', ['username'], {})
        if len(result) == 0:
            return True
        else:
            return False

    def first_run(self, username, password):
        key = enc.KeyKeeper._generate_primary_key()
        self.keeper = enc.KeyKeeper(store, key)
        salt, enc_key = self.keeper.update_user_pass(password)
        user = User.new(username, salt, enc_key, 'admin')
        return user

    def unlock(self, username, password):
        try:
            user = User.load(username)
            print(password)
            key = enc.KeyKeeper.decrypt_system_key(password, user.salt, user.enc_key)
            self.keeper = enc.KeyKeeper(store, key)
        except InvalidToken:
            print("Password Incorrect!")
            return False
        except TypeError:
            return False
        
        self.start()

        return True

    def start(self):
        self.cmd = Cmd(self.keeper, self)
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
        try:
            self.net_srv.shutdown()
            self.server_thread.join()
    
            # self.net_srv = None
            del self.server_thread
            del self.net_srv
            self.status = "stopped"
        except:
            return [False, 'Service is not running']
        return [True]

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
