import datetime

from pki_tools import SHA512, Validity, Name, Certificate, RSAKeyPair

cert = Certificate(
    subject=Name(cn=["Cert CN"]),
    issuer=Name(cn=["Cert CN"]),
    validity=Validity(
        not_before=datetime.datetime.today() - datetime.timedelta(days=1),
        not_after=datetime.datetime.today() + datetime.timedelta(days=1),
    ),
)

cert.sign(RSAKeyPair.generate(), SHA512)

from pki_tools import OCSPRequest

req = OCSPRequest(
    hash_algorithm=SHA512.algorithm, serial_number=cert.serial_number
)

req.create(cert, cert)

print(req.pem_string)
