import socket
import sys
import hashlib
import secrets
from nacl.signing import SignedMessage, SigningKey, VerifyKey
from pathlib import Path
from typing import ByteString, Optional, Tuple, Union

from protocolutil import (
    ALICE_PUBKEY,
    ALICE_SECKEY,
    ALICE_SIGNING_KEY,
    BOB_PUBKEY,
    BOB_SECKEY,
    BOB_SIGNING_KEY,
    SocialistMillionaireTranscript,
    User,
)


class Client:
    def __init__(self, user: User, server_addr: str, server_port: int):
        self.user = user
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server_addr, server_port))

    def secure_send(self, message: str) -> None:
        """Send messsage securely"""
        packet = self.user.sign_message(message)
        self.socket.send(packet.encode())

    def secure_receive(self) -> int:
        """Receive message"""
        packet = self.socket.recv(4096).decode()
        message = self.user.verify_packet(packet)
        if not message:
            raise Exception("ERROR: Received a forged packet.")
        try:
            return int(message)
        except:
            raise Exception("ERROR: Received a non-integer message.")

    def end_session(self):
        self.socket.send("FIN".encode())
        self.socket.close()

    def initiate_smp(self):
        """Initiate secure socialist millionaire protocol"""
        server_response = self.socket.recv(40096).decode()
        if server_response == "FIN":
            print("> Connection refused.")
            self.socket.close()
            return
        print("\n>", server_response, self.user.name, "\n")
        print("> Hashing your password file, please wait...\n")
        self.user.hashed_filecontent = self.user.hash_file_as_int()
        soc_millionaire = SocialistMillionaireTranscript(
            secret=self.user.hashed_filecontent,
            is_first_sender=self.user.name == "alice",  # Assume alice is the first sender in SMP
        )
        input("> Done\n\n> Press enter to begin SMP\n")
        # User subscripts
        SND_SUBSCRIPT = "a" if self.user.name == "alice" else "b"
        RCV_SUBSCRIPT = "b" if self.user.name == "alice" else "a"
        SND_S = "s" if self.user.name == "alice" else "r"
        RCV_R = "r" if self.user.name == "alice" else "s"
        SND_FILE = "hash(alice file)" if self.user.name == "alice" else "hash(bob file)"
        RCV_FILE = "hash(bob file)" if self.user.name == "alice" else "hash(alice file)"
        # Log messages
        A2_COMPUTED = "> Computed random secret {}2\n".format(SND_SUBSCRIPT)
        G1_A2_SNT = "> Sent g1^{}2\n".format(SND_SUBSCRIPT)
        G1_B2_RCV = "> Received g1^{}2\n".format(RCV_SUBSCRIPT)
        G2_COMPUTED = "> Computed shared secret g2 = g1^({}2 * {}2)\n".format(
            RCV_SUBSCRIPT, SND_SUBSCRIPT
        )
        A3_COMPUTED = "> Computed random secret {}3\n".format(SND_SUBSCRIPT)
        G1_A3_SNT = "> Sent g1^{}3\n".format(SND_SUBSCRIPT)
        G1_B3_RCV = "> Received g1^{}3\n".format(RCV_SUBSCRIPT)
        G3_COMPUTED = "> Computed shared secret g3 = g1^({}3 * {}3)\n".format(
            RCV_SUBSCRIPT, SND_SUBSCRIPT
        )
        R_COMPUTED = "> Computed random secret {}\n".format(SND_S)
        PA_SNT = "> Send P{} = g3^{}\n".format(SND_SUBSCRIPT, SND_S)
        PB_RCV = "> Received P{} = g3^{}\n".format(RCV_SUBSCRIPT, RCV_R)
        QA_SNT = "> Send Q{} = g1^{} * g2^{}\n".format(SND_SUBSCRIPT, SND_S, SND_FILE)
        QB_RCV = "> Received Q{} = g1^{} * g2^{}\n".format(RCV_SUBSCRIPT, RCV_R, RCV_FILE)
        RA_SNT = "> Send R{} = (Qa / Qb)^{}3\n".format(SND_SUBSCRIPT, SND_SUBSCRIPT)
        RB_RCV = "> Received R{} = (Qa / Qb)^{}3\n".format(RCV_SUBSCRIPT, RCV_SUBSCRIPT)
        RAB_COMPUTED = "> Computed shared secret Rab = R{}^{}3\n".format(
            RCV_SUBSCRIPT, SND_SUBSCRIPT
        )
        print(A2_COMPUTED)
        self.secure_send(str(soc_millionaire.g1_a2))
        print(G1_A2_SNT)
        soc_millionaire.g1_b2 = self.secure_receive()
        if soc_millionaire.g1_b2 == 1:
            raise Exception("ERROR: Received a poisoned message.")
        print(G1_B2_RCV)
        print(G2_COMPUTED)
        print(A3_COMPUTED)
        self.secure_send(str(soc_millionaire.g1_a3))
        print(G1_A3_SNT)
        soc_millionaire.g1_b3 = self.secure_receive()
        print(G1_B3_RCV)
        print(G3_COMPUTED)
        print(R_COMPUTED)
        self.secure_send(str(soc_millionaire.Pa))
        print(PA_SNT)
        soc_millionaire.Pb = self.secure_receive()
        print(PB_RCV)
        self.secure_send(str(soc_millionaire.Qa))
        print(QA_SNT)
        soc_millionaire.Qb = self.secure_receive()
        print(QB_RCV)
        self.secure_send(str(soc_millionaire.Ra))
        print(RA_SNT)
        soc_millionaire.Rb = self.secure_receive()
        print(RB_RCV)
        print(RAB_COMPUTED)
        print("> Comparing Rab with (Pa / Pb)...\n")
        print(
            "> The password files are equal\n"
            if soc_millionaire.is_secret_equal()
            else "> The password files are not equal\n"
        )
        self.end_session()

    def initiate_interactive_mode(self):
        server_response = self.socket.recv(40096).decode()
        if server_response == "FIN":
            print("> Connection refused.")
            self.socket.close()
            return
        print("\n>", server_response, self.user.name, "\n")
        while True:
            message = input("Enter a text:\n> ")
            self.secure_send(message)
            print("")
            message = self.secure_receive()
            print("Received a text:\n> {}\n".format(message))


if __name__ == "__main__":
    # Validation
    if len(sys.argv) < 3:
        print("Please specify the username, server address, and port number")
        sys.exit(-1)
    # Input parsing
    user_name = sys.argv[1].lower()
    server_addr = sys.argv[2]
    server_port = int(sys.argv[3])
    # Validation
    if user_name not in ["alice", "bob"]:
        print('Please enter "alice" or "bob" as a username for this simulation')
        sys.exit(-1)
    # User
    user = User(
        name=user_name,
        x=ALICE_SECKEY if user_name == "alice" else BOB_SECKEY,
        signing_key=ALICE_SIGNING_KEY if user_name == "alice" else BOB_SIGNING_KEY,
        pubkey=ALICE_PUBKEY if user_name == "alice" else BOB_PUBKEY,
        rcv_pubkey=BOB_PUBKEY if user_name == "alice" else ALICE_PUBKEY,
        filepath=Path("files") / (user_name + "-passwords.txt"),
    )
    # Client
    client = Client(user=user, server_addr=server_addr, server_port=server_port)
    try:
        # client.initiate_interactive_mode()
        client.initiate_smp()
    except Exception as e:
        print(str(e), "Aborting session...")
        client.end_session()
    except KeyboardInterrupt:
        print("Session ended")
        client.end_session()
    # client.initiate_smp()
