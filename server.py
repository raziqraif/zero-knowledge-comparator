from datetime import datetime
from enum import Enum
import mimetypes
from nacl.encoding import HexEncoder
import os
from pathlib import Path
import signal
import socket
from subprocess import Popen, PIPE
import sys
import threading
from typing import Any, List, Union


class Connection:
    """Model a connection and provide some APIs that can be used by
    connection handlers
    """

    BUFFER_SIZE = 4096

    def __init__(self, socket, address):
        """Constructor"""

        self.socket = socket
        self.address = address

    def read_message(self) -> Union[str, Any]:
        """Read a message from client (until a line break is found)"""

        message = self.socket.recv(self.BUFFER_SIZE)
        try:
            message = message.decode().strip()
        except:
            print("Failed to decode message.\n")
        return message

    def send_message(self, message):
        """Send a message to client"""

        if isinstance(message, str):
            message = message.encode()
        self.socket.send(message)

    def kill_client(self):
        """Kill localhost process(es) listening to the port specified
        in self.address
        """

        port = self.address[1]
        process = Popen(["lsof", "-i", ":{0}".format(port)], stdout=PIPE, stderr=PIPE)
        stdout = process.communicate()[0]
        for process in str(stdout.decode("utf-8")).split("\n")[1:]:
            data = [x for x in process.split(" ") if x != ""]
            if len(data) <= 1:
                continue
            os.kill(int(data[1]), signal.SIGKILL)


class WorkerThread(threading.Thread):
    """Service an incoming connection"""

    def __init__(self, connection: Connection, connections: List[Connection], connections_mutex):
        """Constructor"""

        super().__init__()
        self.connections = connections
        self.connections_mutex = connections_mutex
        self.snd_connection = connection

    @property
    def rcv_connection(self) -> Connection:
        # Set this as a property bcs connections list may not contain the receiver's
        # connection yet when the thread was spawned
        self.connections_mutex.acquire()
        connection = [
            connection for connection in self.connections if connection != self.snd_connection
        ][0]
        self.connections_mutex.release()
        return connection

    def run(self):
        """Forward any incoming message from sender's connection to
        the receiver's connection"""
        self.snd_connection.send_message("Welcome")
        while True:
            message = self.snd_connection.read_message()
            print("Received message from {}: \n> {}\n".format(self.snd_connection.address, message))
            if message == "FIN":
                self.snd_connection.socket.close()
                self.connections_mutex.acquire()
                self.connections.remove(self.snd_connection)
                self.connections_mutex.release()
                print("Ended connection with {}\n".format(self.snd_connection.address))
                break
            if len(self.connections) > 1:
                self.rcv_connection.send_message(message)


class Server:
    """Model a server"""

    MAX_QUEUED_CONNECTIONS = 10

    def __init__(self, port: int):
        # Init socket
        self.port = port
        self.socket = socket.socket()
        self.socket.bind(("", port))
        self.socket.listen(self.MAX_QUEUED_CONNECTIONS)
        # Track connections
        self.connections_mutex = threading.Lock()
        self.connections = []
        self.threads = []
        print("Socket created. Listening on port {}\n".format(port))

    def listen(self):
        while True:
            connection_socket, address = self.socket.accept()
            print("Got connection from", address, "\n")
            # Ignore connections after two parties have connected
            if len(self.connections) == 2:
                connection_socket.send("FIN".encode())
                connection_socket.close()
                print("Ended connection with {}\n".format(address))
                continue
            connection = Connection(connection_socket, address)
            self.connections_mutex.acquire()
            self.connections.append(connection)
            self.connections_mutex.release()
            thread = WorkerThread(connection, self.connections, self.connections_mutex)
            self.threads.append(thread)
            thread.start()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Please specify the port number")
        sys.exit(-1)

    port = int(sys.argv[1])
    server = Server(port)
    server.listen()
