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

import datetime
import os
from tinyec import registry
import tinyec.ec as elc
import secrets

import SplitECIES
from SplitECIES import SplitKEM_KeyGen, Split_Encaps, Split_Decaps, Split_Reconst
from SplitECIES import ECIES_enc, ECIES_dec,point_x_bytes, point_y_bytes, bytes_to_point, privkey_to_pkPoint


#Certificate builder (self signed)

def Cert_builder(key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"Fi"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Uusima"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Helsinki"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Our Team"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
    # Our certificate will be valid for 90 days
        datetime.datetime.utcnow() + datetime.timedelta(days=90)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())
    return cert







def save_key_to_file(key, password, filename):
 
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    
    with open(filename, 'wb') as f:
        f.write(pem)

        
        
        
# Generate Alice keys


KeysA=SplitKEM_KeyGen()

KeyA=KeysA[0]
KeyA1=KeysA[1]
KeyA2=KeysA[2]

# Make Alice certificate

CertA= Cert_builder(KeyA)

#Generate Bob's key and certificate

KeyB=ec.generate_private_key(ec.SECP256R1(), default_backend())

CertB= Cert_builder(KeyB)




# Create path to Alice1 and Alice2 keys 
file_pathA1 = os.path.expanduser("FILE_PATH")  
file_nameA1 = "keyA1.pem"
full_pathA1 = os.path.join(file_pathA1, file_nameA1)

file_pathA2 = os.path.expanduser("FILE_PATH")  
file_nameA2 = "keyA2.pem"
full_pathA2 = os.path.join(file_pathA2, file_nameA2)


# Save the keys to a file with a password
passwordA1 = "A1pass"
save_key_to_file(KeyA1, passwordA1, full_pathA1)
passwordA2 = "A2pass"
save_key_to_file(KeyA2, passwordA2, full_pathA2)



# Create path to Bob's key
file_pathB = os.path.expanduser("FILE_PATH")  
file_nameB = "keyB.pem"
full_pathB = os.path.join(file_pathB, file_nameB)
# Save the keys to a file with a password
passwordB = "Bpass"
save_key_to_file(KeyB, passwordB, full_pathB)




# Save Alice Cert
file_pathcerta = os.path.expanduser("FILE_PATH")  
file_namecerta = "CertA.pem"
full_pathcerta = os.path.join(file_pathcerta, file_namecerta)
with open(full_pathcerta, "wb") as f:
    f.write(CertA.public_bytes(serialization.Encoding.PEM))
    
    
# Save Bob Cert
file_pathcertb = os.path.expanduser("FILE_PATH")  
file_namecertb = "CertB.pem"
full_pathcertb = os.path.join(file_pathcertb, file_namecertb)
with open(full_pathcertb, "wb") as f:
    f.write(CertB.public_bytes(serialization.Encoding.PEM))