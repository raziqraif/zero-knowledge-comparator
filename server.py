from datetime import datetime
from enum import Enum
import mimetypes 
import os
from pathlib import Path
import signal
import socket
from subprocess import Popen, PIPE
import sys
import threading


class Connection: 
    """ Model a connection and provide some APIs that can be used by 
        connection handlers
     """ 
    
    BUFFER_SIZE = 4096

    def __init__(self, socket, address):
        """ Constructor """

        self.socket = socket
        self.address = address
    
    def read_message(self) -> str:
        """ Read a message from client (until a line break is found) """ 

        message = self.socket.recv(self.BUFFER_SIZE)
        message = message.decode()
        message = message.strip()
        return message

    def make_io_nonblocking(self):
        """ Prevent io operations from blocking """ 

        self.socket.setblocking(False)
   
    def make_io_blocking(self):
        """ Prevent io operations from blocking """ 

        self.socket.setblocking(True)

    def send_message(self, message):
        """ Send a message to client """ 

        if isinstance(message, str):
            message = message.encode()
        self.socket.send(message)

    def kill_client(self):
        """ Kill localhost process(es) listening to the port specified
            in self.address
        """
       
        port = self.address[1]
        process = Popen(["lsof", "-i", ":{0}".format(port)], stdout=PIPE,
                        stderr=PIPE)
        stdout = process.communicate()[0]
        for process in str(stdout.decode("utf-8")).split("\n")[1:]:       
            data = [x for x in process.split(" ") if x != '']
            if (len(data) <= 1):
                continue

            os.kill(int(data[1]), signal.SIGKILL)


class ConnectionHandler:
    """ Base abstract class for handling a connection. 

        It is protocol-agnostic and must not be instantiated. Instantiate the 
        child of this class instead, depending on the protocol used in  
        the connection 
    """

    def __init__(self, connection: Connection):
        """ Constructor """

        self.connection: Connection = connection

    def handle_connection(self):
        """ Must be overridden by subclass """

        raise Exception("Method needs to be overridden by subclass") 


class PAHandler (ConnectionHandler):
    """ Handle connection described in Part A of the lab """

    HELLO_MSG = "HELLO"
    QUIT_MSG = "QUIT"
    WELCOME_MSG = "Welcome!"
    UNKNOWN_MSG = "Unknown message received"

    def __init__(self, connection: Connection, first_message: str):
        """ Constructor """

        super().__init__(connection)
        self._first_message = first_message # The first message was inputted
        # before the instantiation of this class so that the connection 
        # protocol could be determined

    def handle_connection(self):
        # Handle the connection like specified in lab for part A

        message = self._first_message
        while True:
            message = message.upper()
            if message == self.HELLO_MSG:
                response = self.WELCOME_MSG
                self.connection.send_message(response)
            elif message == self.QUIT_MSG:
                self.connection.socket.close()
                self.connection.kill_client()
                break
            else:
                self.connection.send_message(message)

            message = self.connection.read_message()


class WorkerThread (threading.Thread):
    """ Service an incoming connection """

    def __init__(self, connection: Connection):
        """ Constructor """

        super().__init__()
        self.connection = connection
        self.http_lines = []

    def run(self):
        """ Check if the connection is through http or not and create the appropriate
            handler object
        """

        first_message = self.connection.read_message()
        # if self._is_http_request_line(first_message):
        #     request_line = first_message
        #     connection_handler = HTTPHandler(self.connection, request_line)
        # else:
        #     connection_handler = PAHandler(self.connection, first_message)
        connection_handler = PAHandler(self.connection, first_message)
        connection_handler.handle_connection()


class Server:
    """ Model a server """

    MAX_QUEUED_CONNECTIONS = 10

    def __init__(self, port: int):
        self.port = port
        self.socket = socket.socket()
        self.socket.bind(('', port))
        self.socket.listen(self.MAX_QUEUED_CONNECTIONS)

        self.threads = []

        print("Socket created. Listening on port {}".format(port))

    def listen(self):
        while True:
            connection_socket, address = self.socket.accept()
            print ('Got connection from', address)
            connection = Connection(connection_socket, address)
            thread = WorkerThread(connection)
            self.threads.append(thread)
            thread.start()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Please specify the port number")
        sys.exit(-1)

    port = int(sys.argv[1])
    server = Server(port)
    server.listen()
