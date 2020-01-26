import json
import ast
import traceback
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread

HOST = "127.0.0.1"
PORT = 9000
BUFSIZ = 4096
ADDR = (HOST, PORT)

class Server :
    def __init__(self):
        self.connectedUsers = {}
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.bind(ADDR)

    def start(self):
        self.sock.listen(5)
        print("Chat Server has Started !!")
        print("Waiting for connections...")
        accept_thread = Thread(target=self.accept_incoming_connections)
        accept_thread.start()  # Starts the infinite loop.

    def accept_incoming_connections(self):
        """Sets up handling for incoming clients."""
        while True:
            try:
                client, client_address = self.sock.accept()
                print("a client has connected.")
                client.send("You are now connected ! ".encode("utf8"))
                Thread(target=self.handle_client, args=(client,)).start()
            except Exception:
                traceback.print_exc()
                break

    def handle_client(self,conn):  # Takes client socket as argument.
        """Handles a single client connection."""
        print('before recieving')
        data = conn.recv(BUFSIZ).decode("utf8")
        data = json.loads(data)
        name = data['commonName']
        welcome = 'Welcome {} ! '.format(name)
        conn.send(bytes(welcome, "utf8"))
        self.connectedUsers[name] = conn
        while True:
            data = conn.recv(BUFSIZ)
            print(data)
            # data = json.loads(data)
            data = ast.literal_eval(data.decode('utf-8'))
            target = data['commonName']
            msg = data['msg']
            data = {
                'from': name,
                'msg': msg
            }
            data = json.dumps(data).encode("utf-8")
            if target in self.connectedUsers:
                self.connectedUsers[target].sendall(data)


