import socket
import threading
import tkinter as tk

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_pem_public_key


import base64
import datetime
import os

import pickle

#SplitKey dependencies
from tinyec import registry
import secrets
import tinyec.ec as elc

curve = registry.get_curve("secp256r1")

import SplitECIES
from SplitECIES import Split_Encaps, Split_Decaps, Split_Reconst
from SplitECIES import ECIES_enc, ECIES_dec,point_x_bytes, point_y_bytes, bytes_to_point


# Alice2 reads her private key from the encrypted file, converts the key to an integer, then generates her public key (as an EC point)


file_pathA2 = os.path.expanduser("FILE_PATH")  
file_nameA2 = "keyA2.pem"
full_pathA2 = os.path.join(file_pathA2, file_nameA2)

def read_key_from_file(password, filename):
    # Read the contents of the file
    with open(filename, 'rb') as f:
        pem = f.read()

    # Deserialize the private key
    private_key = serialization.load_pem_private_key(
        pem,
        password=password.encode(),
        backend=default_backend()
    )

    return private_key

password='A2pass'
keya=read_key_from_file(password, full_pathA2)

#Alice1 secret key
ska2=keya.private_numbers().private_value

#Alice1 Publickey 

#pka2= ska1 * curve.g



    
#ska2=25552127259261877817950661295876252452470901219602067293391335846272470531061

def Alice2mtoA1(C2x,C2y,ska2):
    # SplitDecap(C2,ska2) using ECIES
    C2=bytes_to_point(C2x,C2y)
    Kp2=Split_Decaps(C2,ska2)
    Kp2x=point_x_bytes(Kp2)
    Kp2y=point_y_bytes(Kp2)
    return Kp2x,Kp2y
    
     
# Define the IP address and port number
IP_ADDRESS = '127.0.0.1'
PORT = 8082

# Create the client socket
client_socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket2.connect((IP_ADDRESS, PORT))

# Receive message from Alice1
Alice1msg = client_socket2.recv(2048)
fromAlice1=pickle.loads(Alice1msg)
#fromAlice1=client_socket2.recv(1024).decode()
print(f"Alice2 received C2 from Alice1")



# Send responce to Alice1
C2x=fromAlice1[0]
C2y=fromAlice1[1]

Kp2x,Kp2y=Alice2mtoA1(C2x,C2y,ska2)

message2Alice1 = pickle.dumps([Kp2x,Kp2y])
client_socket2.send(message2Alice1)
print(f"Alice2 sent Kp2 to Alice1")
print(f"Alice2 message to Alice1 is {len(message2Alice1)} bytes")

