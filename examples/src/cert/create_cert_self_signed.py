import datetime

from pki_tools import Name, Certificate, Validity, RSAKeyPair, SHA512

name = Name(cn=["Cert CN"])

validity = Validity(
    not_before=datetime.datetime.today() - datetime.timedelta(days=1),
    not_after=datetime.datetime.today() + datetime.timedelta(days=1),
)

cert = Certificate(
    subject=name,
    issuer=name,
    validity=validity,
)

cert.sign(RSAKeyPair.generate(), SHA512)

print(cert)
