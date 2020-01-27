import requests
import json
import traceback
import base64
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread,Timer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


PROJECT_DIRECTORY = "/home/ali/Desktop/security/client/"
HOST = "127.0.0.1"
PORT = 9000
BUFSIZ = 4096
ADDR = (HOST, PORT)
users = []
url = "http://127.0.0.1:5000/"





def format_data(data) :
    data = json.dumps(data)
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    return data,headers

class Client :
    def __int__(self):
        self.users = []
        self.sock = None
        self.commonName = ''
        self.username = ''
        self.password = ''

    def set_info(self,commonName,username,password):
        self.commonName = commonName
        self.username = username
        self.password = password

    def sign_up(self):
        data = {
            'commonName': self.commonName,
            'username': self.username,
            'password': self.password
        }
        data, headers = format_data(data)

        r = requests.post(url + "user", data=data, headers=headers)
        r = r.json()
        print(r)
        if ( r['res'] =="success") :
            certif_pem = r['certif']
            key_pem = r['key']
            print("hey")
            with open('{}{}.crt'.format(PROJECT_DIRECTORY, self.commonName), 'wb') as f:
                f.write(str.encode(certif_pem))
            with open('{}{}.pem'.format(PROJECT_DIRECTORY, self.commonName), 'wb') as f:
                f.write(str.encode(key_pem))
            print('done')
        return r

    def sign_in(self):

        certif = open("{}{}.crt".format(PROJECT_DIRECTORY,self.commonName)).read()
        data = {
            'commonName': self.commonName,
            'password': self.password,
            'certif': certif
        }
        data, headers = format_data(data)

        r = requests.post(url + "login", data=data, headers=headers)
        r = r.json()
        print(r)

        return r

    def get_logged_users(self):
        r = requests.get(url + "users")
        r = r.json()
        print(r)
        self.users = r['users']

    def receive(self):
        """ Handles receiving of messages. """
        while True:
            try:
                data = self.sock.recv(BUFSIZ)
                data = json.loads(data)
                messager = data['from']
                crypted = bytes(data['msg'])
                pem_key = open('{}{}.pem'.format(PROJECT_DIRECTORY,self.commonName), 'rb').read()
                private_key = serialization.load_pem_private_key(pem_key, password=None, backend=default_backend())
                decrypted = private_key.decrypt(
                    crypted,
                    padding.OAEP(
                        mgf = padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm = hashes.SHA256(),
                        label = None)
                )
                decrypted = base64.b64decode(decrypted).decode('utf-8')
                print('message from {}  : {}'.format(messager,decrypted))
            except OSError as e:  # Possibly client has left the chat.
                traceback.print_exc()
                break



    def send(self,msg, commonName):
        """ Handles sending of messages. """
        print(len(self.users))
        self.get_logged_users()
        for user in self.users:
            if user['user'] == commonName:
                public_key = serialization.load_pem_public_key(str.encode(user['public_key']),
                                                               backend=default_backend())

        msg = base64.b64encode(str.encode(msg))
        encrypted = public_key.encrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                         algorithm=hashes.SHA256(), label=None))
        data = {
            'commonName': commonName,
            'msg': list(encrypted)
        }
        data = json.dumps(data).encode("utf-8")
        self.sock.sendall(data)

    def test(self):
        self.get_logged_users()
        user = input('user to message : ')
        message= input('message :')

        self.send(message,user)

    def run(self):
        choice = input('1 : for sign in and 2 for sign up')
        choice = int(choice)
        if choice == 1:
            res = self.sign_in()
        else :
            res = self.sign_up()
        print(res)
        if res['res'] == True :
            self.sock = socket(AF_INET, SOCK_STREAM)
            self.sock.connect(ADDR)
            data = {
                'commonName': self.commonName
            }
            data = json.dumps(data).encode("utf-8")
            self.sock.sendall(data)
            receive_thread = Thread(target=self.receive)
            receive_thread.start()
            thread = Timer(5.0, self.test)
            thread.start()






if __name__ == "__main__" :
    commonName = input('Enter username :')
    username = input('enter name :')
    password  = input('enter password : ')
    print("{},{},{}".format(commonName,username,password))
    client = Client()
    client.set_info(commonName,username,password)
    client.run()


# def sign_up() :
#     data = {
#         'commonName': commonName,
#         'username': username,
#         'password': password
#     }
#     data, headers = format_data(data)
#
#     r = requests.post(url + "user", data=data, headers=headers)
#     r = r.json()
#     print(r)
#     return r
#
# def sign_in():
#     data = {
#         'commonName' : commonName,
#         'password' : password,
#         'certif' :  certif
#     }
#     data,headers = format_data(data)
#
#     r = requests.post(url+"login",data = data ,headers =headers)
#     r = r.text
#     print(r)
#     return r
#
#
# def get_logged_users():
#     r = requests.get(url+"users")
#     r = r.json()
#     print(r)
#     return r['users']
#
# #
# #r = test_sign_up()
# # certif =  r['certif']
# # print(certif)
# # test_sign_in()
#
#
#
# def receive():
#     """ Handles receiving of messages. """
#     while True:
#         try:
#             msg = sock.recv(BUFSIZ).decode("utf8")
#             print(msg)
#         except OSError:  # Possibly client has left the chat.
#             break
#
# def first_message(commonName) :
#     data = {
#         'commonName' : commonName
#     }
#     data = json.dumps(data).encode("utf-8")
#     sock.sendall(data)
#
# def send(msg,commonName,users):
#     """ Handles sending of messages. """
#     print (len(users))
#     for user in users :
#         if user['user'] == commonName :
#             public_key=serialization.load_pem_public_key(str.encode(user['public_key']),backend=default_backend())
#             print(user['public_key'])
#
#     encrypted = public_key.encrypt(msg,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
#     data = {
#         'commonName' : commonName,
#         'msg' : list(encrypted)
#     }
#     print(data['msg'])
#     data = json.dumps(data).encode("utf-8")
#     sock.sendall(data)








