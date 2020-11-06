#!/usr/bin/env python

from nacl.signing import SigningKey
from nacl.public import PrivateKey, Box
from nacl.encoding import HexEncoder

f = open('../key_alice', 'rb')
key_alice = f.read(32)
f.close()

f = open('../key_bob', 'rb')
key_bob = f.read(32)
f.close()

ed25519_private_key = SigningKey(key_alice)
ed25519_public_key = ed25519_private_key.verify_key

print(f"Ed25519\nprivate: {ed25519_private_key.encode(HexEncoder).decode('ascii')}\npublic: {ed25519_public_key.encode(HexEncoder).decode('ascii')}")

curve25519_private_key = ed25519_private_key.to_curve25519_private_key()
curve25519_public_key = ed25519_public_key.to_curve25519_public_key()

print(f"Curve25519\nprivate: {curve25519_private_key.encode(HexEncoder).decode('ascii')}\npublic: {curve25519_public_key.encode(HexEncoder).decode('ascii')}")

print("NaCl")

alice_private_key = curve25519_private_key
alice_public_key = alice_private_key.public_key
bob_private_key = SigningKey(key_bob).to_curve25519_private_key()
bob_public_key = bob_private_key.public_key

message = b"kill all humans!"

f = open('../nonce', 'rb')
nonce = f.read(Box.NONCE_SIZE)
f.close()

bob_box = Box(alice_private_key, bob_public_key)
encrypted = bob_box.encrypt(message, nonce, HexEncoder)

print(f"Encrypted: {encrypted.decode('ascii')}")

alice_box = Box(bob_private_key, alice_public_key)
decrypted = alice_box.decrypt(encrypted, encoder=HexEncoder)

print(f"Decrypted: {decrypted.decode('ascii')}")
