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

import socket
import threading
import tkinter as tk
import base64
import datetime
import os
import pickle
import time
import socket


#SplitKey dependencies
from tinyec import registry
import secrets
import tinyec.ec as elc

curve = registry.get_curve("secp256r1")

import SplitECIES
from SplitECIES import Split_Encaps, Split_Decaps, Split_Reconst
from SplitECIES import ECIES_enc, ECIES_dec,point_x_bytes, point_y_bytes, bytes_to_point, pubkey_to_Point



# Bob reads his private key from the encrypted file, converts the key to an integer, then generates her public key (as an EC point)


file_pathB = os.path.expanduser("FILE_PATH")  
file_nameB = "keyB.pem"
full_pathB = os.path.join(file_pathB, file_nameB)

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

password='Bpass'
keyb=read_key_from_file(password, full_pathB)

#Bob secret key
skb=keyb.private_numbers().private_value

#Bob Publickey 

#pkb= skb * curve.g


# Read Bob's Cert
file_pathcertb = os.path.expanduser("~/Desktop/InterProcess/SPLIT_Key/CertB")  
file_namecertb = "CertB.pem"
full_pathcertb = os.path.join(file_pathcertb, file_namecertb)
with open(full_pathcertb, 'rb') as f:
    pem_datacB = f.read()
    certB = x509.load_pem_x509_certificate(pem_datacB)









#Bob has pkb=certB,skb. Got Enc,Mac0,C0,PkA from Alice
def Bobm1(certB,skb,C0x,C0y,Enc,mac,PKA):
    # Bob's public key
    pkbob=certB.public_key()
    #Bobs Public key as a point
    pkb=pubkey_to_Point(pkbob)
    #reconstruct C0 as a point
    C0= bytes_to_point(C0x,C0y)
    CertBob=certB.public_bytes(serialization.Encoding.PEM)
    
    
    
    #Decrypt CertA
    certA,K0=ECIES_dec(Enc,mac,C0,skb)
    Alice_cert=x509.load_pem_x509_certificate(certA)
    
        #Check certA (with this method we only check the issuer (here Alice=CA) and the signature, i.e., no expiring date check...etc.)
    Alice_cert.verify_directly_issued_by(Alice_cert)
    
    # Re-construct pka (as a point on the curve)
    pkA=Alice_cert.public_key()
    pka=pubkey_to_Point(pkA)
   
    
 
        
        # Encap(PkA) using ECIES (with crypto library)
                       #Bob generates a pair of eph public/private keys
    B_eph_private_key =  ec.generate_private_key(ec.SECP256R1())
    C1=B_eph_private_key.public_key()
                        #Shared key
    shared_keyB = B_eph_private_key.exchange(ec.ECDH(),PKA)
        # Key derivation.
    XKDFB = X963KDF(algorithm=hashes.SHA512(),length=256,sharedinfo=shared_keyB)
    K1: bytes = XKDFB.derive(shared_keyB)
        
        
        
        #SPLITencaps(pka)
    C2,K2= Split_Encaps(pka)

    
    # Serialization
    
    C11=C1.public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    # C2 is a point on the curve, we prepare its x and y coordinates in bytes to be sent to Alice
    C2x=point_x_bytes(C2)
    C2y=point_y_bytes(C2)
    
    #Derive the key K
    L=[K0,K1,K2,certA,CertBob]
    K=K0
    for i in range(4):
        kdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=K)
        K= kdf.derive(L[i+1])
        #Compute mac1
    
        # MAC
    Mac = hmac.HMAC(K, hashes.SHA256())
    #Note that in the mac we only consider the x coordinate of C0 and C2
    L1=[C0x,C11,C2x,certA,CertBob]
    
    for i in range(5):
        mac1=Mac.update(L1[i])
    mac1=Mac.finalize()
   

            
    return C11, C2x,C2y, mac1, K, certA

#Bob Last Check

def Bobcheck(certA,certB,C0x,C11,C2x,K,mac2):
    CertBob=certB.public_bytes(serialization.Encoding.PEM)
 
    L=[C0x,C11,C2x, CertBob,certA]
    Mac2b = hmac.HMAC(K, hashes.SHA256())
    for i in range(5):
        Mac2b.update(L[i])
    return Mac2b.verify(mac2)

    

# Define the IP address and port number
IP_ADDRESS = '127.0.0.1'
PORT = 8081

# Create the client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP_ADDRESS, PORT))








# Receive message 1 from Alice
message1 = client_socket.recv(6048)
start_time=time.time()
Alicemsg1=pickle.loads(message1)


C0x=Alicemsg1[0]
C0y=Alicemsg1[1]
Enc=Alicemsg1[2]
mac=Alicemsg1[3]
PkA=load_pem_public_key(Alicemsg1[4])
print(f"Bob received Alice's first message: (PKa,C0,Enc)")


# Send response to the Alice
M2=Bobm1(certB,skb,C0x,C0y,Enc,mac,PkA)
C1=M2[0]
C2x=M2[1]
C2y=M2[2]
mac1=M2[3]
K=M2[4] 
certA=M2[5]

Bmsg1=[C1,C2x,C2y,mac1]
Bobmsg2 = pickle.dumps(Bmsg1)

client_socket.send(Bobmsg2)
print(f"Bob sent his first message to Alice: (C1,C2, Mac1)")
print(f"Bob first message to Alice is {len(Bobmsg2)} bytes")
print(f"Bob's key is: {K}")
# Receive message 2 from Alice
mac2 = client_socket.recv(6048)
#Alicemsg2=pickle.loads(message2)

print(f"Bob received Alice's 2nd message: mac2")




## Last Check

Bobcheck(certA,certB,C0x,C1,C2x,K,mac2)
print(f"Protocol Success")
end_time=time.time()
total_time = end_time - start_time
total_timef=round(total_time, 3)
#mstime=total_time/1000
print("Total time taken :", total_timef, "s")


    
 

key = K  # 128-bit key for AES encryption

# AES encryption function
def encrypt(message, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key[:16]), modes.CTR(key[16:32]), backend=backend)
    encryptor = cipher.encryptor()
    padded_message = message + ' ' * (16 - len(message) % 16)  # PKCS7 padding
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()

# AES decryption function
def decrypt(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message.encode())
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key[:16]), modes.CTR(key[16:32]), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return base64.b64encode(decrypted_message).decode()


def send_message():
    message = entry.get()
    encrypted_message = encrypt(message, key)
    client_socket.send(encrypted_message.encode())
    chat_box.insert(tk.END, f"Bob's plaintext: {message}\n")
    chat_box.insert(tk.END, f"Bob's encryption: {encrypted_message}\n")
    entry.delete(0, tk.END)




def receive_messages():
    while True:
        encrypted_message = client_socket.recv(4096).decode()
        decrypted_message = decrypt(encrypted_message, key)
        chat_box.insert(tk.END, f"Alice's encrypted msg: {encrypted_message}\n")
        base64_string = decrypted_message
        base64_bytes = base64_string.encode('ascii')
        decoded_bytes = base64.b64decode(base64_bytes)
        decoded_string = decoded_bytes.decode('ascii')
        chat_box.insert(tk.END, f"Alice's decrypted msg: {decrypted_message}\n")
        chat_box.insert(tk.END, f"Alice's plaintext: {decoded_string}\n")


bob_window = tk.Tk()
bob_window.title("Bob's SplitKey Chat")



chat_box = tk.Text(bob_window, width=70, height=20)
chat_box.pack()
entry = tk.Entry(bob_window, width=70)
entry.pack()
send_button = tk.Button(bob_window, text="Send", command=send_message)
send_button.pack()


# Start a thread for receiving messages
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

tk.mainloop()
client_socket.close()
