# pkc.py
import os
import sys
import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from eth_abi import encode

def hex_to_bin(hex_string):
    return binascii.unhexlify(hex_string)

if len(sys.argv) != 2:
    print("Not all arguments supplied. Please provide the private key.")
    sys.exit(1)

private_key = sys.argv[1]

if not private_key.isdigit() or int(private_key) <= 0:
    print("Invalid input. The private key must be a valid large positive number.")
    sys.exit(1)

if not private_key.isdigit():
    print("Invalid input. The private key must be a valid large number.")
    sys.exit(1)

private_key = ec.derive_private_key(int(private_key), ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
public_key_coordinates = public_key.public_numbers()
x = public_key_coordinates.x
y = public_key_coordinates.y

encoded_coordinates = encode(['uint256', 'uint256'], [x, y])
encoded_coordinates_hex = binascii.hexlify(encoded_coordinates).decode()
print(encoded_coordinates_hex)