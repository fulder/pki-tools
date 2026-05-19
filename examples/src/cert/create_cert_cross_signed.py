import datetime

from pki_tools import Name, Certificate, Validity, RSAKeyPair, SHA512

issuer_key = RSAKeyPair.generate()
issuer = Name(cn=["Issuer"])

cert_key = RSAKeyPair.generate()
name = Name(cn=["Cert CN"])

validity = Validity(
    not_before=datetime.datetime.today() - datetime.timedelta(days=1),
    not_after=datetime.datetime.today() + datetime.timedelta(days=1),
)

cert = Certificate(
    subject=name,
    issuer=issuer,
    validity=validity,
)

cert.sign(issuer_key, SHA512, req_key=cert_key.public_key)

print(cert)
