from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from ourJWT import OUR_class, OUR_exception

def keygen():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    print (f"Generated private key : {private_key}")
    public_key = private_key.public_key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(pem)
    return private_key_bytes.decode()

PRIVKEY = keygen()

with open('public_key.pem', 'rb') as f:
    PUBKEY = f.read()


encoder: OUR_class.Encoder
decoder: OUR_class.Decoder

try:
    encoder = OUR_class.Encoder(PRIVKEY)
    decoder = OUR_class.Decoder(PUBKEY)
    print(f"created both encoder and decoder object")
except OUR_exception.NoKey:
    print("NO KEY ERROR")
    exit
