import re
from typing import Union

from cryptography import x509

from pki_tools import exceptions
from pki_tools import ocsp
from pki_tools import crl
from pki_tools import types

from loguru import logger


PEM_REGEX = re.compile(r"-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+")
URI_REGEX = re.compile(r"https*://.*")


def cert_from_pem(cert_pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(cert_pem.encode())
    except ValueError as e:
        raise exceptions.CertLoadError(e)


def _is_uri(check):
    return _check_str(URI_REGEX, check)


def _is_pem_str(check):
    return _check_str(PEM_REGEX, check)


def _check_str(pattern, check):
    if not isinstance(check, str):
        return False

    return re.match(pattern, check)


def is_revoked(
    cert: Union[x509.Certificate, types.PemCert],
    issuer_cert: Union[x509.Certificate, types.PemCert, types.Uri] = None,
) -> bool:
    if issuer_cert is not None:
        try:
            return ocsp.is_revoked(cert, issuer_cert)
        except exceptions.ExtensionMissing:
            logger.debug("OCSP Extension missing, trying CRL next")

    try:
        return crl.is_revoked(cert)
    except exceptions.ExtensionMissing:
        err_msg = (
            "OCSP and CRL extensions not found, "
            "couldn't check revocation status"
        )
        logger.error(err_msg)
        raise exceptions.Error(err_msg)
