from pki_tools import (
    Name,
    CertificateSigningRequest,
    RSAKeyPair,
    SHA512,
)

name = Name(cn=["Cert CN"])

csr = CertificateSigningRequest(subject=name)

csr.sign(RSAKeyPair.generate(), SHA512)

print(csr.pem_string)
