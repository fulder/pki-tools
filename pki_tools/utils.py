import httpx


from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.x509.ocsp import OCSPResponse
from loguru import logger

from pki_tools.types.certificate import Certificate
from pki_tools.exceptions import InvalidSignedType, SignatureVerificationFailed
from pki_tools.types.crl import CertificateRevocationList

HTTPX_CLIENT = httpx.Client(
    transport=httpx.HTTPTransport(retries=2), timeout=15
)


def verify_signature(
    signed: [Certificate, CertificateRevocationList, OCSPResponse],
    issuer: Certificate,
) -> None:
    """
    Verifies a signature of a signed entity against the issuer certificate

    Args:
        signed: The signed certificate can either be a
        [Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
        [CertificateRevocationList](https://pki-tools.fulder.dev/pki_tools/types/#certificaterevocationlist)
        or a
        [OCSPResponse](https://pki-tools.fulder.dev/pki_tools/types/#ocspresponse)
        issuer: The
        [Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
        describing the issuer of the signed entity
    Raises:
        [InvalidSignedType](https://pki-tools.fulder.dev/pki_tools/exceptions/#invalidsignedtype)
        -- When the issuer has a non-supported type
        [SignatureVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#signatureverificationfailed)
        -- When the signature verification fails
    """
    issuer_public_key = issuer.public_key

    tbs_bytes = None
    if isinstance(signed, x509.Certificate):
        tbs_bytes = signed.tbs_certificate_bytes
    elif isinstance(signed, x509.CertificateRevocationList):
        tbs_bytes = signed.tbs_certlist_bytes
    elif hasattr(signed, "tbs_response_bytes"):
        tbs_bytes = signed.tbs_response_bytes
    else:
        raise InvalidSignedType(type(signed))

    try:
        issuer_public_key.verify(
            signed.signature,
            tbs_bytes,
            padding.PKCS1v15(),
            signed.signature_hash_algorithm,
        )
        logger.trace("Signature valid")
    except Exception as e:
        logger.bind(
            exceptionType=type(e).__name__,
            exception=str(e),
        ).error("Signature verification failed")
        raise SignatureVerificationFailed(
            f"signature doesn't match issuer"
            f"with subject: {issuer.subject.rfc4514_string()}"
        )
