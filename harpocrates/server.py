from srv.net import ThreadServer
from srv.user import User
from srv.store import Store
from srv.cmd import Cmd
import enc
import threading


# HOST, PORT = "localhost", 9999
# 
# keeper = enc.KeyKeeper(None)
# keeper.first_run_key()
# store = Store()
# 
# 
# salt, password = keeper.update_user_pass('password')
# user = User.new('testadmin', salt, password, "admin", store)
# 
# 
# net_srv = ThreadServer((HOST, PORT), keeper)
# 
# with net_srv:
#     ip, port = net_srv.server_address
#     server_thread = threading.Thread(target=net_srv.serve_forever)
#     server_thread.daemon = False
#     server_thread.start()
#     # Activate the server; this will keep running until you
#     # interrupt the program with Ctrl-C
#     print("server running")
#     input("sdf")
#     print("shuting down")
#     net_srv.shutdown()

class Main():

    def __init__(self,):
        HOST, PORT = "localhost", 9999
        # self.store = Store()
        self.keeper = enc.KeyKeeper(None)
        self.keeper.first_run_key()
        self.cmd = Cmd()
        self.net_srv = ThreadServer((HOST, PORT), self.cmd)
        self.counter = 0

    def test_run(self):
        salt, enc_key = self.keeper.update_user_pass('password')
        # user = User.new('testadmin', salt, enc_key, "admin", Store())
        ip, port = self.net_srv.server_address
        server_thread = threading.Thread(target=self.net_srv.serve_forever)
        server_thread.daemon = False
        server_thread.start()
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        print("server running")
        input("sdf")
        print("shuting down")
        self.net_srv.shutdown()


if __name__ == "__main__":

    main = Main()
    main.test_run()