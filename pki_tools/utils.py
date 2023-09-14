from cryptography import x509

import crl
from pki_tools import exceptions
from pki_tools import ocsp

from loguru import logger


def cert_from_pem(cert_pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(cert_pem.encode())
    except ValueError as e:
        raise exceptions.CertLoadError(e)


def check_revoked(cert_pem: str, issuer_cert_pem: str = None):
    cert = cert_from_pem(cert_pem)
    issuer_cert = None
    if issuer_cert_pem is not None:
        issuer_cert = cert_from_pem(issuer_cert_pem)

    check_revoked_crypto_cert(cert, issuer_cert)


def check_revoked_crypto_cert(
    cert: x509.Certificate, issuer_cert: x509.Certificate = None
):
    if issuer_cert is not None:
        try:
            ocsp.check_revoked_crypto_cert(cert, issuer_cert)
        except exceptions.ExtensionMissing:
            logger.debug("OCSP Extension missing, trying CRL next")

    try:
        crl.check_revoked_crypto_cert(cert)
    except exceptions.ExtensionMissing:
        err_msg = (
            "OCSP and CRL extensions not found, "
            "couldn't check revocation status"
        )
        logger.error(err_msg)
        raise exceptions.Error(err_msg)
