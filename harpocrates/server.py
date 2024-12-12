import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
from srv.net import ThreadServer
from srv.user import User
from srv.store import Store
from srv.cmd import Cmd
import enc
import threading


class Main():

    def __init__(self,):
        HOST, PORT = "localhost", 9999
        self.store = Store()
        password = input("password:")
        try:
            user = User.load("testadmin", self.store)
            print(user)
            key = enc.KeyKeeper.decrypt_system_key(password, user.salt, user.enc_key)
            self.keeper = enc.KeyKeeper(self.store, key)
        except InvalidToken:
            print("Password Incorrect!")
            return
        except TypeError:
            key = enc.KeyKeeper._generate_primary_key()
            self.keeper = enc.KeyKeeper(self.store, key)
            salt, enc_key = self.keeper.update_user_pass(password)
            user = User.new('testadmin', salt, enc_key, 'admin', self.store)
        
        print("system key:")
        print(key)
        
        user.salt, user.enc_key = self.keeper.update_user_pass('password')
        user.save()
        # self.keeper.first_run_key()
        self.cmd = Cmd(self.keeper, self.store)
        # self.cmd.keeper.first_run_key()
        self.net_srv = ThreadServer((HOST, PORT), self.cmd)
        self.counter = 0

    def test_run(self):
        
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