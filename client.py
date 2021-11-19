import socket
import sys


class Client:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, server_name: str, server_port: int):
        self.socket.connect((server_name, server_port))
        while (True):
            sentence = input("Input 'hello' or 'quit': ")
            while len(sentence) == 0:
              sentence = input()
            self.socket.send(sentence.encode())
            sentence = self.socket.recv(1024)
            print(sentence.decode())
        self.socket.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Please specify the server ip address and port number");
        sys.exit(-1)

    server_name = sys.argv[1]
    server_port = int(sys.argv[2])
    
    client = Client()
    client.connect(server_name, server_port)

