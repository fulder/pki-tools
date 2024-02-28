import httpx

from loguru import logger

from pki_tools.types.certificate import Certificate
from pki_tools.exceptions import SignatureVerificationFailed
from pki_tools.types.crl import CertificateRevocationList
from pki_tools.types.ocsp import OCSPResponse
from pki_tools.types.signature_algorithm import PKCS1v15Padding

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
    try:
        issuer.public_key.verify(
            signed._x509_obj.signature,
            signed.tbs_bytes,
            PKCS1v15Padding()._to_cryptography(),
            signed._x509_obj.signature_hash_algorithm,
        )
        logger.trace("Signature valid")
    except Exception as e:
        logger.bind(
            exceptionType=type(e).__name__,
            exception=str(e),
        ).error("Signature verification failed")
        raise SignatureVerificationFailed(
            f"signature doesn't match issuer "
            f"with subject: {str(issuer.subject)}"
        )
