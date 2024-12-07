from srv.net import ThreadServer
import threading

HOST, PORT = "localhost", 9999

net_srv = ThreadServer((HOST, PORT))

with net_srv:
    ip, port = net_srv.server_address
    server_thread = threading.Thread(target=net_srv.serve_forever)
    server_thread.daemon = False
    server_thread.start()
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    print("server running")
    input("sdf")
    print("shuting down")
    net_srv.shutdown()
