import datetime

from pki_tools import SHA512, Certificate, Name, RSAKeyPair, Validity

cert_key_pair = RSAKeyPair.generate()
cert = Certificate(
    subject=Name(cn=["Cert CN"]),
    issuer=Name(cn=["Cert CN"]),
    validity=Validity(
        not_before=datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=1),
        not_after=datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=1),
    ),
)

cert.sign(cert_key_pair, SHA512)

from pki_tools import OcspCertificateStatus, OCSPResponse, OcspResponseStatus

res = OCSPResponse(
    response_status=OcspResponseStatus.SUCCESSFUL,
    certificate_status=OcspCertificateStatus.REVOKED,
    issuer_key_hash="ISSUER_HASH",
    revocation_time=datetime.datetime.now(datetime.timezone.utc),
)

res.sign(cert, cert, SHA512, cert_key_pair.private_key, SHA512)

print(res)
