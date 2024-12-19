import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
from srv.auth import Secret
from srv.net import ThreadServer
from srv.user import User
from srv.store import Store
from srv.cmd import Cmd
import enc
import threading


class Main():
    HOST, PORT = "localhost", 9999
    
    def __init__(self,):
        
        self.store = Store()
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
        self.cmd = Cmd(self.keeper, self.store)
        # self.cmd.keeper.first_run_key()
        self.net_srv = ThreadServer((Main.HOST, Main.PORT), self.cmd)
        self.counter = 0

        return True

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


if __name__ == "__main__":

    main = Main()
    main.test_run()