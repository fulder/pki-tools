from . import ocsp
from . import crl
from . import exceptions
from . import types

from typing import Union

from cryptography import x509

from loguru import logger


def cert_from_pem(cert_pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(cert_pem.encode())
    except ValueError as e:
        raise exceptions.CertLoadError(e)


def is_revoked(
    cert: Union[x509.Certificate, types.PemCert],
    issuer_cert: Union[
        x509.Certificate, types.PemCert, types.OcspIssuerUri
    ] = None,
    crl_cache_seconds: int = 3600,
) -> bool:
    """
    Checks if a certificate is revoked using first OCSP and then CRL extensions.
    The `issuer_cert` argument is only needed when OCSP is available and
    should be checked.

    Note that OCSP has precedence to CRL meaning that if OCSP check is
    successful this function will return the bool without checking CRL.

    Otherwise, if OCSP check fails, CRL will be tried next.

    Arguments:
        cert -- The certificate to check revocation for. Can either be
        a x509.Certificate or a types.PemCert string
        issuer_cert -- Only needed for OCSP, the issuer of the `cert`. Can
        a x509.Certificate, a types.PemCert string or types.OcspIssuerUri
        including the URI to the issuer public cert
    Returns:
        True if the certificate is revoked, False otherwise

    Raises:
        exceptions.OcspFetchFailure -- When OCSP fails preforming the check
        against the server
        exceptions.OcspIssuerFetchFailure -- When `issuer_cert` is of
        exceptions.OcspIssuerUri type and fetching the public certificate fails
        exceptions.CrlFetchFailure -- When the CRL could not be fetched
        exceptions.CrlLoadError -- If CRL could be fetched successfully but
        could not be loaded e.g. due invalid format or file
        exceptions.Error -- If revocation check fails both with OCSP and CRL
    """
    if issuer_cert is not None:
        try:
            return ocsp.is_revoked(cert, issuer_cert)
        except exceptions.ExtensionMissing:
            logger.debug("OCSP Extension missing, trying CRL next")

    try:
        return crl.is_revoked(cert, crl_cache_seconds)
    except exceptions.ExtensionMissing:
        err_msg = (
            "OCSP and CRL extensions not found, "
            "couldn't check revocation status"
        )
        logger.error(err_msg)
        raise exceptions.Error(err_msg)
