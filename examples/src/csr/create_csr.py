from pki_tools import (
    SHA512,
    CertificateSigningRequest,
    Name,
    RSAKeyPair,
)

name = Name(cn=["Cert CN"])

csr = CertificateSigningRequest(subject=name)

csr.sign(RSAKeyPair.generate(), SHA512)

print(csr.pem_string)
