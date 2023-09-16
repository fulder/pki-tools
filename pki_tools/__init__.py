from cryptography.hazmat.primitives import serialization

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


def pem_from_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def is_revoked(
    cert: Union[x509.Certificate, types.PemCert],
    issuer_cert: Union[
        x509.Certificate, types.PemCert, types.OcspIssuerUri
    ] = None,
    crl_cache_seconds: int = 3600,
) -> bool:
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


def save_to_file(cert: Union[x509.Certificate, types.PemCert], file_path: str):
    if isinstance(cert, x509.Certificate):
        cert = pem_from_cert(cert)

    with open(file_path, "w") as f:
        f.write(cert)

    logger.debug(f"Certificate saved to {file_path}")


def read_from_file(file_path: str) -> x509.Certificate:
    with open(file_path, "r") as f:
        cert_pem = f.read()
        return cert_from_pem(cert_pem)
