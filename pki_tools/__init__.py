from collections import defaultdict

from cryptography.hazmat.primitives import serialization

from . import ocsp
from . import crl
from . import exceptions
from . import types

from typing import Union

from cryptography import x509

from loguru import logger


def cert_from_pem(cert_pem: str) -> x509.Certificate:
    """
    Loads a certificate from a PEM string into a x509.Certificate object

    Arguments:
        cert_pem -- The PEM encoded certificate in string format
    Returns:
        A x509.Certificate created from the PEM
    Raises:
         exceptions.CertLoadError - If the certificate could not be loaded
    """
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
        issuer_cert -- [OCSP Only] The issuer of the `cert`. Can be a
        x509.Certificate, a types.PemCert string or types.OcspIssuerUri
        including the URI to the issuer public cert
        crl_cache_seconds -- [CRL Only] Specifies how long the CRL should be
        cached, default is 1 hour.
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


def save_to_file(cert: Union[x509.Certificate, types.PemCert], file_path: str):
    """
    Saves a certificate into a file

    Arguments:
        cert -- The certificate to save to the `file_path`. Can either be
        a x509.Certificate or a types.PemCert string
        file_path -- Path and filename where to store the certificate
    """
    if isinstance(cert, x509.Certificate):
        cert = pem_from_cert(cert)

    with open(file_path, "w") as f:
        f.write(cert)

    logger.debug(f"Certificate saved to {file_path}")


def read_from_file(file_path: str) -> x509.Certificate:
    """
    Reads a file containing a PEM certificate into a x509.Certificate object.

    Arguments:
        file_path -- Path and filename of the PEM certificate
    Returns:
         A x509.Certificate representing the certificate from file
    """
    with open(file_path, "r") as f:
        cert_pem = f.read()
        return cert_from_pem(cert_pem)


def parse_subject(cert: [x509.Certificate, types.PemCert]) -> types.Subject:
    """
    Parses a certificate and returns a types.Subject containing all the
    attributes present in
    [RFC5280#Section-4.1.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4)

    Arguments:
        cert -- The certificate to check revocation for. Can either be
        a x509.Certificate or a types.PemCert string
    Returns:
        A types.Subject with all the available attributes
    """
    if types._is_pem_str(cert):
        cert = cert_from_pem(cert)

    cert_dict = defaultdict(set)
    for attribute in cert.subject:
        for att in cert.subject.get_attributes_for_oid(attribute.oid):
            cert_dict[att.oid.dotted_string].add(att.value)

    return types.Subject(**cert_dict)
