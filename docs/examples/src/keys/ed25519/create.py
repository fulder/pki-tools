from pki_tools import Ed25519KeyPair

key_pair = Ed25519KeyPair.generate()

print(key_pair.private_key.pem_string)
print(key_pair.public_key.pem_string)
