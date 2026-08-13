from pki_tools import RSAKeyPair

key_pair = RSAKeyPair.generate()

print(key_pair.private_key.pem_string)
print(key_pair.public_key.pem_string)
