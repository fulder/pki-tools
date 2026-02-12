from pki_tools import Ed448KeyPair

key_pair = Ed448KeyPair.generate()

print(key_pair.private_key.pem_string)
print(key_pair.public_key.pem_string)
