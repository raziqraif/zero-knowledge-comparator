import socket
import sys
import hashlib
import secrets
from pathlib import Path
from typing import Union


def hash(text: str) -> str:
    hasher = hashlib.sha3_512()
    hasher.update(bytes(text, "utf-8"))
    return hasher.hexdigest()


def hash_as_int(text: str) -> int:
    return int(hash(text), 16)


class PublicKey:
    def __init__(self, p=7, g=2, gX=4):
        self.p = p  # prime
        self.q = p - 1  # order of group
        self.g = g  # generator of group
        self.gX = gX  # generator raised to secret key


class SocialistMillionaireTranscript:
    def __init__(self, secret: int, shared_pubkey: PublicKey, is_first_sender=True):
        self.secret = secret
        self.is_first_sender = is_first_sender
        # Shared public key
        self.p = shared_pubkey.p
        self.q = shared_pubkey.q
        self.g = shared_pubkey.g
        # First transaction - secret
        self.a2 = secrets.randbits(512)
        self.a3 = secrets.randbits(512)
        # First transaction - received
        self.g1_b2 = 0
        self.g1_b3 = 0
        # Second transaction - secret
        self.s = secrets.randbits(512)
        # Second transaction - received
        self.Pb = 0
        self.Qb = 0
        # Third transaction - received
        self.Rb = 0

    # First transaction - send data

    @property
    def g1_a2(self) -> int:
        return pow(self.g, self.a2, self.p)

    @property
    def g1_a3(self) -> int:
        return pow(self.g, self.a3, self.p)

    # First transaction - shared secret

    @property
    def g2(self) -> int:
        return pow(self.g1_a2, self.g1_b2, self.p)

    @property
    def g3(self) -> int:
        return pow(self.g1_a3, self.g1_b3, self.p)

    # Second transaction - send data

    @property
    def Pa(self) -> int:
        return pow(self.g3, self.s, self.p)

    @property
    def Qa(self) -> int:
        product = pow(self.g, self.s, self.p) * pow(self.g2, self.secret, self.p)
        return product % self.p

    # Third transaction - send data

    @property
    def Ra(self) -> int:
        numerator = self.Qa if self.is_first_sender else self.Qb
        denominator = self.Qb if self.is_first_sender else self.Qa
        product = numerator * pow(denominator, -1, self.p) % self.p
        return pow(product, self.a3, self.p)

    # Third transaction - shared secret

    @property
    def R(self) -> int:
        return pow(self.Rb, self.a3, self.p)

    def is_secret_equal(self) -> bool:
        numerator = self.Pa if self.is_first_sender else self.Pb
        denominator = self.Pb if self.is_first_sender else self.Pa
        product = numerator * pow(denominator, -1, self.p) % self.p
        return self.R == product


class User:
    def __init__(
        self,
        x: int,
        pubkey: PublicKey,
        rcv_pubkey: PublicKey,
        filepath: Path,
        is_first_sender: bool = True,
    ):
        # Private key
        self.x = x  # secret
        # Public key
        self.pubkey = pubkey
        self.rcv_pubkey = rcv_pubkey
        # Hashed file
        self.hashed_filecontent = self.hash_file_as_int(filepath)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_first_sender = is_first_sender

    def send(self, message: Union[str, int]) -> None:
        """Send messsage securely"""
        message = str(message)
        tag = self.sign_message(message)
        tag = str(tag)
        self.socket.send(message.encode())
        self.socket.send(tag.encode())

    def receive(self) -> int:
        message = self.socket.recv(1024).decode()
        tag = self.socket.recv(1024).decode()

    def initiate(self, server_name: str, server_port: int):
        """Initiate secure socialist millionaire protocol"""
        self.socket.connect((server_name, server_port))
        soc_millionaire = SocialistMillionaireTranscript(
            secret=self.hashed_filecontent,
            shared_pubkey=PublicKey(),
            is_first_sender=self.is_first_sender,
        )
        self.send(soc_millionaire.g1_a2)
        self.send(soc_millionaire.g1_a3)
        soc_millionaire.g1_b2 = self.receive()
        soc_millionaire.g1_b3 = self.receive()
        self.send(soc_millionaire.Pa)
        self.send(soc_millionaire.Qa)
        soc_millionaire.Pb = self.receive()
        soc_millionaire.Qb = self.receive()
        self.send(soc_millionaire.Ra)
        soc_millionaire.Rb = self.receive()
        print(
            "The files are equal"
            if soc_millionaire.is_secret_equal()
            else "The files are not equal"
        )
        self.socket.close()

    def sign_message(self, msg: str) -> tuple[int, int]:
        """Sign message based on Schnorr's signature"""
        k = secrets.randbits(512)
        r = pow(self.pubkey.g, k, self.pubkey.p)
        e = hash_as_int(str(r) + msg)
        s = k - self.x * e
        return s, e

    def verify_message(self, msg: str, tag: tuple[int, int], pubkey: PublicKey) -> bool:
        """Verify message based on Schnorr's signature"""
        s, e = tag
        r_v = pow(pubkey.g, s, pubkey.p) * pow(pubkey.gX, e, pubkey.p) % pubkey.p
        e_v = hash_as_int(str(r_v) + msg)
        return e == e_v

    def hash_file_as_int(self, filepath: Path) -> int:
        """Hash a file as integer"""
        BUF_SIZE = 65536  # 64kB
        hasher = hashlib.sha3_512()
        with open(filepath, "rb") as file:
            while True:
                data = file.read(BUF_SIZE)
                if not data:
                    break
                hasher.update(data)
        return int(hasher.hexdigest(), 16)


class UserClient:
    def __init__(self, user: User):
        self.user = user
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, server_name: str, server_port: int):
        self.socket.connect((server_name, server_port))
        while True:

            sentence = input("Password file name': ")
            while len(sentence) == 0:
                sentence = input()
            self.socket.send(sentence.encode())
            sentence = self.socket.recv(1024)
            print(sentence.decode())
        self.socket.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Please specify the server ip address and port number")
        sys.exit(-1)

    server_name = sys.argv[1]
    server_port = int(sys.argv[2])
    user_name = sys.argv[3]

    client = UserClient()
    client.connect(server_name, server_port)
