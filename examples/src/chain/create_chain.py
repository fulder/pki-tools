import datetime

from pki_tools import (
    Name,
    RSAKeyPair,
    SHA512,
    Chain,
    Certificate,
    Validity,
)

issuer_key = RSAKeyPair.generate()
issuer = Name(cn=["Issuer"])

validity = Validity(
    not_before=datetime.datetime.today() - datetime.timedelta(days=1),
    not_after=datetime.datetime.today() + datetime.timedelta(days=1),
)

# Create self-signed issuer cert
issuer_cert = Certificate(
    subject=issuer,
    issuer=issuer,
    validity=validity,
)
issuer_cert.sign(issuer_key, SHA512)

cert_key = RSAKeyPair.generate()
name = Name(cn=["Cert CN"])

# Create certificate singed by issuer key
cert = Certificate(
    subject=name,
    issuer=issuer,
    validity=validity,
)
cert.sign(issuer_key, SHA512, req_key=cert_key.public_key)

chain = Chain(certificates=[issuer_cert, cert])

print(chain)
