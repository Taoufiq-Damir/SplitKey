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



#SplitKey dependencies
from tinyec import registry
import secrets
import tinyec.ec as elc

curve = registry.get_curve("secp256r1")

import SplitECIES
from SplitECIES import Split_Encaps, Split_Decaps, Split_Reconst
from SplitECIES import ECIES_enc, ECIES_dec,point_x_bytes, point_y_bytes, bytes_to_point, pubkey_to_Point

import socket
import threading
import tkinter as tk

import base64
import datetime
import os
import time
# Alice1 reads her private key from the encrypted file, converts the key to an integer, then generates her public key (as an EC point)


file_pathA1 = os.path.expanduser("FILE_PATH")  
file_nameA1 = "keyA1.pem"
full_pathA1 = os.path.join(file_pathA1, file_nameA1)

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

password='A1pass'
keya=read_key_from_file(password, full_pathA1)

#Alice1 secret key
ska1=keya.private_numbers().private_value

#Alice1 Publickey 

pka1= ska1 * curve.g


# Read Alice Cert
file_pathcerta = os.path.expanduser("~/Desktop/InterProcess/SPLIT_Key/CertA")  
file_namecerta = "CertA.pem"
full_pathcerta = os.path.join(file_pathcerta, file_namecerta)
with open(full_pathcerta, 'rb') as f:
    pem_datacA = f.read()
    certA = x509.load_pem_x509_certificate(pem_datacA)


# Alice's public key
pkalice=certA.public_key()

#Alice public key as point
pka=pubkey_to_Point(pkalice)


# Read Bob's Cert
file_pathcertb = os.path.expanduser("~/Desktop/InterProcess/SPLIT_Key/CertB")  
file_namecertb = "CertB.pem"
full_pathcertb = os.path.join(file_pathcertb, file_namecertb)
with open(full_pathcertb, 'rb') as f:
    pem_datacB = f.read()
    certB = x509.load_pem_x509_certificate(pem_datacB)


# Bob's public key
pkbob=certB.public_key()

#Bobs Public key (as point)
pkb=pubkey_to_Point(pkbob)







 
  
   

## Message 1 by Alice
def Alicem1(pka,pkb):
        
        #Alice generates a pair of public/private keys
        SKA =  ec.generate_private_key(ec.SECP256R1())
        PKA=SKA.public_key()
    
    
        # ECIES KEM1(encrypt CertA)
        C,Enc,mac, K0=ECIES_enc(pkb,certA.public_bytes(serialization.Encoding.PEM))
        C0x=point_x_bytes(C)
        C0y=point_y_bytes(C)
        
        

        return C0x,C0y, Enc, mac, PKA, SKA, K0
    
    
    

## Message 2 (responce to Bob) by Alice


def Alicem2(pka,ska1,certA,certB,SKA,K0,C0x,C0y,C1,C2x,C2y,mac1,Kp2x,Kp2y):
    CertAlice=certA.public_bytes(serialization.Encoding.PEM)
    certB=certB.public_bytes(serialization.Encoding.PEM)
    
    # Decap(C1,SKA) using ECIES
    #Shared key
    shared_keyA1 = SKA.exchange(ec.ECDH(),C1)
        # Key derivation.
    XKDFB = X963KDF(algorithm=hashes.SHA512(),length=256,sharedinfo=shared_keyA1)
    K1: bytes = XKDFB.derive(shared_keyA1)
        
    # SplitDecap(C2,ska) using ECIES
    C2=bytes_to_point(C2x,C2y)
    Kpp2=Split_Decaps(C2,ska1)
        
    #reconstruct Splitkey
    Kp2= bytes_to_point(Kp2x,Kp2y)
    K2=Split_Reconst(Kp2,Kpp2)
    #Derive the key K
    L=[K0,K1,K2,CertAlice, certB]
    K=K0
    for i in range(4):
        kdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=K)
        K= kdf.derive(L[i+1])
    #Compute mac1
   
    C11=C1.public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
  
        # Check mac1
    L1=[C0x,C11,C2x,CertAlice, certB]
            
    Mac = hmac.HMAC(K, hashes.SHA256())
   
    
    for i in range(5):
        Mac.update(L1[i])
        
            #check mac
            
    Mac.verify(mac1)
            
    L=[C0x,C11,C2x, certB,CertAlice]
    Mac2 = hmac.HMAC(K, hashes.SHA256())
    for i in range(5):
        Mac2.update(L[i])
    mac2=Mac2.finalize()
    return mac2, K
           
          
                
            
            
    
    


 
      


## Socket communication

import socket
import pickle

# Define the IP address and port numbers
IP_ADDRESS = '127.0.0.1'
PORT1 = 8081
PORT2 = 8082
# Create the server sockets
server_socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket1.bind((IP_ADDRESS, PORT1))
server_socket1.listen()
server_socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket2.bind((IP_ADDRESS, PORT2))
server_socket2.listen()





# Accept the connection with Bob
client_socket1, address1 = server_socket1.accept()
print(f"Connection established with Bob with address {address1}")
print(f"Alice sent her first message to Bob: (PKa, C0, Enc)")

# Send message 1 to Bob
start_time=time.time()
Alice_msg1=Alicem1(pka,pkb)

C0x=Alice_msg1[0]
C0y=Alice_msg1[1]
Enc=Alice_msg1[2]
mac=Alice_msg1[3]
PKA=Alice_msg1[4]
SKA=Alice_msg1[5]
K0=Alice_msg1[6]

PkAa=PKA.public_bytes(Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
M1=[C0x,C0y, Enc, mac,PkAa]
message1 = pickle.dumps(M1)
print(f"Alice first message to Bob is {len(message1)} bytes")
end_time=time.time()
total_time = end_time - start_time
total_timef=round(total_time, 3)
#mstime=total_time/1000
print("Total time taken by Alice to produce the first message is :", total_timef, "s")


client_socket1.send(message1)



# Receive response from Bob
response1 = client_socket1.recv(2048)
Bobresp1=pickle.loads(response1)
print(f"Alice received Bob's first message: (C1,C2, Mac1)")



C1=load_pem_public_key(Bobresp1[0])
C2x=Bobresp1[1]
C2y=Bobresp1[2]
mac1=Bobresp1[3]



# Accept the connection with Alice2
client_socket2, address2 = server_socket2.accept()
print(f"Connection established with Alice2 with address {address2}")

# Forward C2 to Alice2
M22=[C2x,C2y]
message2Alice2 = pickle.dumps(M22)

client_socket2.send(message2Alice2)
print(f"Alice1 sent C2 to Alice2")
print(f"Alice1 message to Alice2 is {len(message2Alice2)} bytes")


# Receive response from Alice2
Alice2Resp = client_socket2.recv(2048)
A2resp=pickle.loads(Alice2Resp)
print(f"Alice received responce from Alice2: Kp2 ")


# Send responce to Bob
Kp2x=A2resp[0]
Kp2y=A2resp[1]
Alice_msg2=Alicem2(pka,ska1,certA,certB,SKA,K0,C0x,C0y,C1,C2x,C2y,mac1,Kp2x,Kp2y)
M2=Alice_msg2[0]
#message2 = pickle.dumps(M2)
client_socket1.send(M2)
K=Alice_msg2[1]
print(f"Alice sent her last message: mac2")
print(f"Alice last message is {len(M2)} bytes")

print(f"Protocol Success")
print(f"Alice's key is: {K}")






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

# Function to handle sending messages
def send_message():
    message = entry.get()
    encrypted_message = encrypt(message, key)
    client_socket1.send(encrypted_message.encode())
    chat_box.insert(tk.END, f"Alice's plaintext: {message}\n")
    chat_box.insert(tk.END, f"Alice's encryption: {encrypted_message}\n")
    entry.delete(0, tk.END)


def receive_messages():
    while True:
        encrypted_message = client_socket1.recv(4096).decode()
        decrypted_message = decrypt(encrypted_message, key)
        chat_box.insert(tk.END, f"Bob's encrypted msg: {encrypted_message}\n")
        chat_box.insert(tk.END, f"Bob's decrypted msg: {decrypted_message}\n")
        base64_string = decrypted_message
        base64_bytes = base64_string.encode('ascii')
        decoded_bytes = base64.b64decode(base64_bytes)
        decoded_string = decoded_bytes.decode('ascii')
        chat_box.insert(tk.END, f"Bob's plaintext: {decoded_string}\n")


alice_window = tk.Tk()
alice_window.title("Alice's SplitKey Chat")

key = K  # 128-bit key for AES encryption


chat_box = tk.Text(alice_window, width=70, height=20)
chat_box.pack()
entry = tk.Entry(alice_window, width=70)
entry.pack()
send_button = tk.Button(alice_window, text="Send", command=send_message)
send_button.pack()




receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

tk.mainloop()
