import datetime

from pki_tools import Name, Certificate, Validity, RSAKeyPair, SHA512

name = Name(cn=["Cert CN"])

cert = Certificate(
    subject=name,
    issuer=name,
    validity=Validity(
        not_before=datetime.datetime.today(),
        not_after=datetime.datetime.today() + datetime.timedelta(days=1),
    ),
)

cert.sign(RSAKeyPair.generate(), SHA512)

print(cert.pem_string)
