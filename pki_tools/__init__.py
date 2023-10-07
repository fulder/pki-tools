import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.ocsp import OCSPResponse

from . import ocsp
from . import crl
from . import exceptions

from .types.certificate import Certificate, Subject
from .types import Chain, PemCert, _is_pem_str

from typing import Union, List

from cryptography import x509

from loguru import logger

HTTPX_CLIENT = httpx.Client(
    transport=httpx.HTTPTransport(retries=2), timeout=15
)


def cert_from_pem(cert_pem: str) -> x509.Certificate:
    """
    Loads a certificate from a PEM string into a
    [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
    object

    Arguments:
        cert_pem -- The PEM encoded certificate in string format
    Returns:
        A
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        created from the PEM
    Raises:
         exceptions.CertLoadError - If the certificate could not be loaded
    """
    try:
        return x509.load_pem_x509_certificate(cert_pem.encode())
    except ValueError as e:
        logger.bind(cert=cert_pem).debug("Failed to load cert from PEM")
        raise exceptions.CertLoadError(e)


def pem_from_cert(cert: x509.Certificate) -> str:
    """
    Converts a cert type into a PEM string

    Arguments:
        cert -- The
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        certificate
    Returns:
        A string representing the PEM encoded certificate
    """
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def is_revoked_multiple_issuers(
    cert: Union[x509.Certificate, PemCert],
    cert_issuer: Chain,
    ocsp_issuer: Chain,
    crl_issuer: Chain,
    crl_cache_seconds: int = 3600,
):
    """
    Checks if a certificate is revoked first using the OCSP extension and then
    the CRL extensions.

    Note that OCSP has precedence over CRL meaning that if OCSP check is
    successful this function will return the bool without checking CRL.

    Otherwise, if OCSP check fails, CRL will be tried next.

    Arguments:
        cert -- The certificate to check revocation for. Can either be
        a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        or a
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        string
        cert_issuer -- The CA chain including one or more certificates and
        the issuer of the `cert`. See
        [types.Chain](https://pki-tools.fulder.dev/pki_tools/types/#chain)
        for examples how the chain can be created
        ocsp_issuer -- The CA chain including one or more certificates used
        for signing of the OCSP response
        crl_issuer -- The CA chain including one or more certificates used
        for signing the CRL
        crl_cache_seconds -- [CRL Only] Specifies how long the CRL should be
        cached, default is 1 hour.
    Returns:
        True if the certificate is revoked, False otherwise
    Raises:
        [exceptions.ChainVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#chainverificationfailed)
        -- When the Chain contains more than one certificate and
        the trust fails either because of some certificate has expired
        or some signature in the chain is invalid

        [exceptions.RevokeCheckFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#revokecheckfailed)
        -- When both OCSP and CRL checks fail
    """

    try:
        return ocsp._is_revoked_multiple_issuers(
            cert, cert_issuer, ocsp_issuer
        )
    except (
        exceptions.ExtensionMissing,
        exceptions.OcspInvalidResponseStatus,
        exceptions.OcspFetchFailure,
        exceptions.OcspIssuerFetchFailure,
    ):
        logger.debug("OCSP revoke check failed, trying CRL next")

    try:
        return crl._is_revoked(cert, crl_issuer)
    except exceptions.Error as e:
        err_message = "OCSP and CRL checks failed"
        logger.bind(exceptionType=type(e).__name__).error(err_message)
        raise exceptions.RevokeCheckFailed(err_message) from None


def is_revoked(
    cert: Union[x509.Certificate, PemCert],
    chain: Chain,
    crl_cache_seconds: int = 3600,
) -> bool:
    """
    Checks if a certificate is revoked first using the OCSP extension and then
    the CRL extensions.

    Note that OCSP has precedence over CRL meaning that if OCSP check is
    successful this function will return the bool without checking CRL.

    Otherwise, if OCSP check fails, CRL will be tried next.

    Arguments:
        cert -- The certificate to check revocation for. Can either be
        a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        or a
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        string
        chain -- The CA chain including one or more certificates and
        the issuer of the `cert`, signer of the OCSP response and CRL
        issuer. See
        [types.Chain](https://pki-tools.fulder.dev/pki_tools/types/#chain)
        for examples how the chain can be created
        crl_cache_seconds -- [CRL Only] Specifies how long the CRL should
        be cached, default is 1 hour.
    Returns:
        True if the certificate is revoked, False otherwise
    Raises:
        [exceptions.ChainVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#chainverificationfailed)
        -- When the Chain contains more than one certificate and
        the trust fails either because of some certificate has expired
        or some signature in the chain is invalid

        [exceptions.RevokeCheckFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#revokecheckfailed)
        -- When both OCSP and CRL checks fail
    """
    return is_revoked_multiple_issuers(
        cert, chain, chain, chain, crl_cache_seconds
    )


def save_to_file(
    certs: Union[List[x509.Certificate], List[PemCert]], file_path: str
):
    """
    Saves one or more certificate(s) into a file

    Arguments:
        cert -- A list of certificate(s) to save to the `file_path`. Can either
        be a list of
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        or a list of
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        file_path -- Path and filename where to store the certificate(s)
    """
    convert = isinstance(certs[0], x509.Certificate)

    with open(file_path, "w") as f:
        for cert in certs:
            if convert:
                cert = pem_from_cert(cert)

            f.write(cert)

    logger.debug(f"Certificate(s) saved to {file_path}")


def read_from_file(file_path: str) -> x509.Certificate:
    """
    Reads a file containing one PEM certificate into a
    [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
    object

    Arguments:
        file_path -- Path and filename of the PEM certificate
    Returns:
         The
         [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
         representing the certificate from file
    """

    return read_many_from_file(file_path)[0]


def read_many_from_file(file_path: str) -> List[x509.Certificate]:
    """
    Reads a file containing one or more PEM certificate(s) into a list of
    [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
    object

    Arguments:
        file_path -- Path and filename of the PEM certificate
    Returns:
         A list of
         [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
         representing the certificate(s) from file
    """
    with open(file_path, "r") as f:
        cert_pem = f.read()

    return x509.load_pem_x509_certificates(cert_pem.encode())


def parse_certificate(cert: [x509.Certificate, PemCert]) -> Certificate:
    """
    Parses a certificate and returns a
    [types.Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
    containing all the
    fields specified by
    [RFC5280#Section-4.1.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1)

    Arguments:
        cert: The certificate to check revocation for. Can either be
        a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        or a
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        string
    Returns:
        A [types.Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
        with all the available attributes
    """
    if _is_pem_str(cert):
        cert = cert_from_pem(cert)

    return Certificate.parse_certificate(cert)


def verify_signature(
    signed: [x509.Certificate, x509.CertificateRevocationList, OCSPResponse],
    issuer: x509.Certificate,
) -> None:
    """
    Verifies a signature of a signed entity agains the issuer certificate

    Args:
        signed: The signed certificate can either be a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate),
        [x509.CertificateRevocationList](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.CertificateRevocationList)
        or a
        [x509.CertificateRevocationList](https://cryptography.io/en/latest/x509/ocsp/#cryptography.x509.ocsp.OCSPResponse)
        issuer: The issuer of the signed entity
    Raises:
        [exceptions.InvalidSignedType](https://pki-tools.fulder.dev/pki_tools/exceptions/#invalidsignedtype)
        -- When the issuer has a non-supported type
        [exceptions.SignatureVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#signatureverificationfailed)
        -- When the signature verification fails
    """
    issuer_public_key = issuer.public_key()

    tbs_bytes = None
    if isinstance(signed, x509.Certificate):
        tbs_bytes = signed.tbs_certificate_bytes
    elif isinstance(signed, x509.CertificateRevocationList):
        tbs_bytes = signed.tbs_certlist_bytes
    elif hasattr(signed, "tbs_response_bytes"):
        tbs_bytes = signed.tbs_response_bytes
    else:
        raise exceptions.InvalidSignedType(type(signed))

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
        raise exceptions.SignatureVerificationFailed(
            f"signature doesn't match issuer"
            f"with subject: {issuer.subject.rfc4514_string()}"
        )
