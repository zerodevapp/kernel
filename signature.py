import os
import sys
import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from eth_abi import encode

def hex_to_bin(hex_string):
    return binascii.unhexlify(hex_string)

if len(sys.argv) != 3:
    print("Not all arguments supplied. Please provide the hash to be signed and private key.")
    sys.exit(1)

hash_to_be_signed = sys.argv[1]
private_key = sys.argv[2]

# Remove '0x' prefix if present
if hash_to_be_signed.startswith('0x'):
    hash_to_be_signed = hash_to_be_signed[2:]

if not all(c in '0123456789abcdefABCDEF' for c in hash_to_be_signed):
    print("Invalid input. The hash must be a valid hexadecimal string.")
    sys.exit(1)

# Check if private key is a positive integer
if not private_key.isdigit() or int(private_key) <= 0:
    print("Invalid input. The private key must be a positive integer.")
    sys.exit(1)

private_key = ec.derive_private_key(int(private_key), ec.SECP256R1(), default_backend())
hash_to_be_signed_bytes = hex_to_bin(hash_to_be_signed)
signature = private_key.sign(hash_to_be_signed_bytes, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
r, s = utils.decode_dss_signature(signature)

encoded_sig = encode(['uint256', 'uint256'], [r, s])

# print encoded_sig as hex string
encoded_sig_hex = binascii.b2a_hex(encoded_sig).decode()
print(encoded_sig_hex)