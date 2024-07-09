from tinyec import registry
import tinyec.ec as elc
import secrets
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.backends import default_backend

curve = registry.get_curve("secp256r1")

def point_x_bytes(point):
    x_bytes = int.to_bytes(point.x, (point.curve.field.p.bit_length() + 7) // 8, 'big')
    return x_bytes
def point_y_bytes(point):
    y_bytes = int.to_bytes(point.y, (point.curve.field.p.bit_length() + 7) // 8, 'big')
    return y_bytes

def bytes_to_point(x_bytes,y_bytes):
    x=int.from_bytes(x_bytes, "big", signed=False)
    y=int.from_bytes(y_bytes, "big", signed=False)
    point=elc.Point(curve,x,y)
    return point

def pubkey_to_Point(pk):
    PKa_int = pk.public_numbers()
# Get the x and y coordinates
    x_coordinate = PKa_int.x
    y_coordinate = PKa_int.y

    x_bytes=x_coordinate.to_bytes((x_coordinate.bit_length() + 7) // 8, 'big')
    y_bytes=y_coordinate.to_bytes((y_coordinate.bit_length() + 7) // 8, 'big')
    return bytes_to_point(x_bytes,y_bytes)

def privkey_to_pkPoint(key):
    pka_crypto=key.public_key()
    PKa_int = pka_crypto.public_numbers()
# Get the x and y coordinates
    x_coordinate = PKa_int.x
    y_coordinate = PKa_int.y

    x_bytes=x_coordinate.to_bytes((x_coordinate.bit_length() + 7) // 8, 'big')
    y_bytes=y_coordinate.to_bytes((y_coordinate.bit_length() + 7) // 8, 'big')
    return bytes_to_point(x_bytes,y_bytes)




def SplitKEM_KeyGen():
    KeyA1=ec.generate_private_key(ec.SECP256R1(), default_backend())
    Ka1=KeyA1.private_numbers().private_value
    
    KeyA2=ec.generate_private_key(ec.SECP256R1(), default_backend())
    Ka2=KeyA2.private_numbers().private_value


    #Construct private key for Alice=keyA1+keyA2
    Ka=Ka1+Ka2
    KeyA =ec.derive_private_key(
        private_value=Ka,
        curve=ec.SECP256R1(),
        backend=default_backend()
        )
    return KeyA, KeyA1, KeyA2

def Split_Encaps(pk):
    PrivKey = secrets.randbelow(curve.field.n)
    C = PrivKey * curve.g
    Ks=PrivKey * pk
    Ksx= point_x_bytes(Ks)
    
    K= HKDF(
            algorithm=hashes.SHA256(),
            length=256,
            salt=None,
            info=None,
            backend= default_backend()
        ).derive(Ksx)
    return C, K

def Split_Decaps(C,sk):
    Ks= sk * C
    return Ks

def Split_Reconst(Ks1,Ks2):
    Ka=Ks1+Ks2
    Ks= point_x_bytes(Ka)
    
    K= HKDF(
            algorithm=hashes.SHA256(),
            length=256,
            salt=None,
            info=None,
            backend= default_backend()
        ).derive(Ks)
    return  K


def ECIES_enc(pk,plain):
    C,K=Split_Encaps(pk)
    cipher = Cipher(algorithms.AES(K[:16]), modes.CTR(K[16:32]), backend = default_backend())
    encryptor = cipher.encryptor()
    Enc = encryptor.update(plain) + encryptor.finalize()
    M = hmac.HMAC(K[32:],hashes.SHA256())
    M.update(Enc)
    mac=M.finalize()
    return C, Enc, mac, K

def ECIES_dec(Enc,mac,C,sk):
    Ks= sk * C
    Ksx= point_x_bytes(Ks)
    K= HKDF(
            algorithm=hashes.SHA256(),
            length=256,
            salt=None,
            info=None,
            backend= default_backend()
        ).derive(Ksx)
    #Check mac
    M = hmac.HMAC(K[32:],hashes.SHA256())
    M.update(Enc)
    M.verify(mac)
    #Decrypt
    cipher = Cipher(algorithms.AES( K[:16]), modes.CTR( K[16:32]), backend=default_backend())
    decryptor = cipher.decryptor()

    plain= decryptor.update(Enc) + decryptor.finalize()
    return plain, K
    
    
    
    
    
    
    