from pki_tools import DSAKeyPair

key_pair = DSAKeyPair.generate(key_size=1024)

print(key_pair.private_key.pem_string)
print(key_pair.public_key.pem_string)
