from pki_tools import (
    Name,
    CertificateSigningRequest,
    RSAKeyPair,
    SHA512,
)

name = Name(cn=["Cert CN"])

csr = CertificateSigningRequest(subject=name)

key_pair = RSAKeyPair.generate()

csr.sign(key_pair.private_key, SHA512)

print(csr.pem_string)
