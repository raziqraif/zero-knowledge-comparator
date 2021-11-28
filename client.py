import socket
import sys
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Tuple, Union


def hash(text: str) -> str:
    hasher = hashlib.sha3_512()
    hasher.update(bytes(text, "utf-8"))
    return hasher.hexdigest()


def hash_as_int(text: str) -> int:
    return int(hash(text), 16)


class PublicKey:
    def __init__(self, p: int, g: int, g_x: int):
        self.p = p  # prime
        self.q = p - 1  # order of group
        self.g = g  # generator of group
        self.g_x = g_x  # generator raised to secret key


class SocialistMillionaireTranscript:
    def __init__(self, secret: int, is_first_sender=True):
        self.secret = secret
        self.is_first_sender = is_first_sender
        # Shared public key
        self.p = 19812107358546665865075788571800041268057238148459671645996831818706737024464580364571694503227453750585850256208084681325431359008538342611831761022582814848454566938721086473007911929523126592783261609111253139428948923751359141590730735374846730803783623562595634073686456302324974542696120362114673769559011412761446436492231098362605461610508005277418373075904567346432319905964816216854326551316234274005831933317439924115438744603550708593834322402996007002747814988560315013640869662395106446441117427040111183588092052767805271264759157968801822492143875759327981555125258537922718698041636056674397410246383
        self.q = self.p - 1
        self.g = 5
        # First transaction - secret
        self.a2 = secrets.randbits(2048)
        self.a3 = secrets.randbits(2048)
        # First transaction - received
        self.g1_b2 = 0
        self.g1_b3 = 0
        # Second transaction - secret
        self.s = secrets.randbits(2048)
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
        name: str,
        x: int,
        pubkey: PublicKey,
        rcv_pubkey: PublicKey,
        filepath: Path,
        is_first_sender: bool = True,
    ):
        self.name = name
        # Private key
        self.x = x  # secret
        # Public key
        self.pubkey = pubkey
        self.rcv_pubkey = rcv_pubkey
        # Hashed file
        self.hashed_filecontent = self.hash_file_as_int(filepath)

    def sign_message(self, msg: str) -> Tuple[int, int]:
        """Sign message based on Schnorr's signature"""
        k = secrets.randbits(2048)
        r = pow(self.pubkey.g, k, self.pubkey.p)
        e = hash_as_int(str(r) + msg) % self.pubkey.q
        s = k + (self.x * e % self.pubkey.q) % self.pubkey.q
        return s, e

    def verify_message(self, msg: str, tag: Tuple[int, ...], pubkey: PublicKey) -> bool:
        """Verify message based on Schnorr's signature"""
        s, e = tag
        r_v = pow(pubkey.g, s, pubkey.p) * pow(pubkey.g_x, e, pubkey.p) % pubkey.p
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
    def __init__(self, user: User, server_addr: str, server_port: int):
        self.user = user
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server_addr, server_port))

    def secure_send(self, message: Union[str, int]) -> None:
        """Send messsage securely"""
        message = str(message)
        tag = self.user.sign_message(message)
        tag = str(tag)
        self.socket.send(message.encode())
        self.socket.send(tag.encode())

    def secure_receive(self) -> int:
        """Receive message"""
        raw_message = self.socket.recv(4096).decode()
        message = raw_message.split("(")[0]
        tag = tuple(
            int(tag_element)
            for tag_element in raw_message.replace("(", "").replace(")", "").split(",")
        )
        print("message = ", message)
        print("s = ", tag[0])
        print("e = ", tag[1])
        assert len(tag) == 2
        if not self.user.verify_message(message, tag, self.user.rcv_pubkey):
            print(Exception("Cannot verify received message."))
        return int(message)

    def end_session(self):
        self.socket.send("FIN".encode())
        self.socket.close()

    def initiate_smp(self):
        """Initiate secure socialist millionaire protocol"""
        soc_millionaire = SocialistMillionaireTranscript(
            secret=self.user.hashed_filecontent,
            is_first_sender=self.user.name == "alice",  # Assume alice is the first sender in SMP
        )
        self.secure_send(soc_millionaire.g1_a2)
        self.secure_send(soc_millionaire.g1_a3)
        soc_millionaire.g1_b2 = self.secure_receive()
        soc_millionaire.g1_b3 = self.secure_receive()
        self.secure_send(soc_millionaire.Pa)
        self.secure_send(soc_millionaire.Qa)
        soc_millionaire.Pb = self.secure_receive()
        soc_millionaire.Qb = self.secure_receive()
        self.secure_send(soc_millionaire.Ra)
        soc_millionaire.Rb = self.secure_receive()
        print(
            "The files are equal"
            if soc_millionaire.is_secret_equal()
            else "The files are not equal"
        )
        self.socket.close()

    def initiate_interactive_mode(self):
        server_response = self.socket.recv(40096).decode()
        if server_response == "FIN":
            print("Connection refused.")
            self.socket.close()
            return
        print(server_response)
        while True:
            if self.user.name == "alice":
                message = input("\nEnter a text:\n> ")
                self.secure_send(message)
            if self.user.name == "bob":
                message = self.secure_receive()
                print("\nReceived a text:\n> {}\n".format(message))


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
    # Alice keys
    ALICE_SECKEY = 25095223584808844526585852956684221589983584207715454267026046864518088929906566114422875834364236875732144374846032562955727790077207258741962197804780042561446855728540275119937759441946528613313868996324987917542745069634830383619110554036572526657393144464125691828996736508063800370186392230551924512026031280229419343957937520713383860689163529728690961391378942846223754376106118416956391211135129044843447811419590900350222636585134201089818283552202400248605414874112053024479614941889624601044378951807253807949377401806066752588899940820739004626754739704328970965474841959363563713889781025180226813274571
    ALICE_PUBKEY = PublicKey(
        p=19122567761531172498895907091633172829966352231599688742980788619876103264366784481197606741604117812713977823111461414476510219868828642519991560118046662527645113287586984774790114086935016971936381488035085676681494598564782347981593388308545108393674154439973091487602479755221480316419938445699467433423640295332632697976819760432331216172426793793283106404186947417595439700830185324716525350646417674410604622252449310712059712725084447664321672552626276639456390591176679155614313622688785984455937996968745644738384942460619147508397446603163984903097122023123074846988477121066054915099862686169266197629003,
        g=2,
        g_x=-1,
    )
    ALICE_PUBKEY.g_x = pow(ALICE_PUBKEY.g, ALICE_SECKEY, ALICE_PUBKEY.p)
    # Bob keys
    BOB_SECKEY = 15940278275072703655970777727067100547921156439907227813104783928909888945761407528259352673150242702762555383621446355412935212739666792658103365508841352265763232203749169549333553537033902174793598196740189150489920643498684668841688791528072980005752044076401381277487549160260475933275672465899170589173709819516091016716570336837623902010162422877367580754368328779183567794176762048023886004492477197145362689595785484664343153078671318626185294206165972242305663909074585080267362102327056589303180615822594263656250624497825244320375755839813564356605518974072770615348675340983445175560960334141992501296130
    BOB_PUBKEY = PublicKey(
        p=17923821986298966014407657826538655385152011349133497552169116709189421317105008957913437351676519532886729646443687523821684988101315510111959271343916236415798312015163307433076162178097585876384518876629844225395872912635921306560378274286135935083856358191486050981211305467532918821849595617821060607778846919389055899822366616327060896670303677640912272557423808144318916079117100399367570622993035233888553512621550881597248643553241929012190111712160372745671213816259823203848227078513917454211445361840329237968338960999590008506865144881419212859634558869105114256049099599702926615141001768531675117850963,
        g=5,
        g_x=-1,
    )
    BOB_PUBKEY.g_x = pow(BOB_PUBKEY.g, BOB_SECKEY, ALICE_PUBKEY.p)
    # User
    user = User(
        name=user_name,
        x=ALICE_SECKEY if user_name == "alice" else BOB_SECKEY,
        pubkey=ALICE_PUBKEY if user_name == "alice" else BOB_PUBKEY,
        rcv_pubkey=BOB_PUBKEY if user_name == "alice" else ALICE_PUBKEY,
        filepath=Path("files") / (user_name + ".txt"),
    )
    # Client
    client = UserClient(user=user, server_addr=server_addr, server_port=server_port)
    try:
        client.initiate_interactive_mode()
    except Exception as e:
        print(str(e), "Aborting session...")
        client.end_session()
    except KeyboardInterrupt:
        print("Session ended")
        client.end_session()
    # client.initiate_smp()
