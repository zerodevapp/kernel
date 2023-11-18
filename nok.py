import os
import sys
import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils

def hex_to_bin(hex_string):
    return binascii.unhexlify(hex_string)

if len(sys.argv) != 3:
    print("Not all arguments supplied. Please provide the hash to be signed and private key.")
    sys.exit(1)

hash_to_be_signed = sys.argv[1]
private_key = sys.argv[2]

if not all(c in '0123456789abcdefABCDEF' for c in hash_to_be_signed) or not all(c in '0123456789abcdefABCDEF' for c in private_key):
    print("Invalid input. The hash and private key must be valid hexadecimal strings.")
    sys.exit(1)

private_key = ec.derive_private_key(int(private_key, 16), ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

public_key_hex = public_key_bytes.decode()
public_key_coordinates = public_key.public_numbers()
x = public_key_coordinates.x
y = public_key_coordinates.y
x_hex = hex(x)
y_hex = hex(y)

# sign with secp256r1
hash_to_be_signed_bytes = hex_to_bin(hash_to_be_signed)
# use prehash to avoid double hashing

signature = private_key.sign(hash_to_be_signed_bytes, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
r, s = utils.decode_dss_signature(signature)
r_hex = hex(r)
s_hex = hex(s)

print(f"Public Key Coordinates: x = {x_hex}, y = {y_hex}")
print(f"Signature: r = {r_hex}, s = {s_hex}")