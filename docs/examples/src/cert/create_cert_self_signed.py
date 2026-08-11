import datetime

from pki_tools import SHA512, Certificate, Name, RSAKeyPair, Validity

name = Name(cn=["Cert CN"])

validity = Validity(
    not_before=datetime.datetime.now(datetime.timezone.utc)
    - datetime.timedelta(days=1),
    not_after=datetime.datetime.now(datetime.timezone.utc)
    + datetime.timedelta(days=1),
)

cert = Certificate(
    subject=name,
    issuer=name,
    validity=validity,
)

cert.sign(RSAKeyPair.generate(), SHA512)

print(cert)
