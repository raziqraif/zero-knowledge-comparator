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
    """Model a connection and provide some APIs that can be used by
    connection handlers
    """

    BUFFER_SIZE = 4096

    def __init__(self, socket, address):
        """Constructor"""

        self.socket = socket
        self.address = address

    def read_message(self) -> str:
        """Read a message from client (until a line break is found)"""

        message = self.socket.recv(self.BUFFER_SIZE)
        message = message.decode()
        message = message.strip()
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

    def __init__(self, connections: list[Connection], index: int):
        """Constructor"""

        super().__init__()
        self.index = index
        self.connections = connections
        self.snd_connection = connections[index]

    @property
    def rcv_connection(self) -> Connection:
        # Set this as a property bcs connections list may not contain the receiver's
        # connection yet when the thread was spawned
        return self.connections[(self.index + 1) % 2]

    def run(self):
        """Forward any incoming message from sender's connection to
        the receiver's connection"""
        while True:
            message = self.snd_connection.read_message()
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
        self.connections = []
        self.threads = []
        print("Socket created. Listening on port {}".format(port))

    def listen(self):
        while True:
            connection_socket, address = self.socket.accept()
            print("Got connection from", address)
            # Ignore connections not from alice or bob
            if len(self.connections) == 2:
                continue
            connection = Connection(connection_socket, address)
            self.connections.append(connection)
            thread = WorkerThread(self.connections, len(self.connections) - 1)
            self.threads.append(thread)
            thread.start()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Please specify the port number")
        sys.exit(-1)

    port = int(sys.argv[1])
    server = Server(port)
    server.listen()
