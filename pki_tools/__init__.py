from collections import defaultdict
from functools import lru_cache

import requests
from cryptography.hazmat.primitives import serialization

from . import ocsp
from . import crl
from . import exceptions
from . import types

from typing import Union, List

from cryptography import x509

from loguru import logger


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
        a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        or a
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        string
        issuer_cert -- [OCSP Only] The issuer of the `cert`. Can be a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        , a
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        string or
        [types.OcspIssuerUri](https://pki-tools.fulder.dev/pki_tools/types/#ocspissueruri)
        including the URI to the issuer public cert
        crl_cache_seconds -- [CRL Only] Specifies how long the CRL should be
        cached, default is 1 hour.
    Returns:
        True if the certificate is revoked, False otherwise
    Raises:
        [exceptions.CrlFetchFailure](https://pki-tools.fulder.dev/pki_tools/exceptions/#crlfetchfailure)
        -- When the CRL could not be fetched

        [exceptions.CrlLoadError](https://pki-tools.fulder.dev/pki_tools/exceptions/#crlloaderror)
        -- If CRL could be fetched successfully but could not be loaded e.g.
        due invalid format or file

        [exceptions.Error](https://pki-tools.fulder.dev/pki_tools/exceptions/#error)
        -- If revocation check fails both with OCSP and CRL

        [exceptions.ExtensionMissing](https://pki-tools.fulder.dev/pki_tools/exceptions/#extensionmissing)
        -- When neither OCSP nor CRL extensions exist

        [exceptions.RevokeCheckFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#revokecheckfailed)
        -- When both OCSP and CRL checks fail
    """
    if issuer_cert is not None:
        try:
            return ocsp.is_revoked(cert, issuer_cert)

        except (
            exceptions.ExtensionMissing,
            exceptions.OcspInvalidResponseStatus,
            exceptions.OcspFetchFailure,
            exceptions.OcspIssuerFetchFailure,
        ):
            logger.debug("OCSP revoke check failed, trying CRL next")

    try:
        return crl.is_revoked(cert, crl_cache_seconds)
    except exceptions.Error as e:
        err_message = "OCSP and CRL checks failed"
        logger.bind(exceptionType=type(e).__name__).error(err_message)
        raise exceptions.RevokeCheckFailed(err_message) from None


def save_to_file(
    certs: Union[List[x509.Certificate], List[types.PemCert]], file_path: str
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


def parse_subject(cert: [x509.Certificate, types.PemCert]) -> types.Subject:
    """
    Parses a certificate and returns a
    [types.Subject](https://pki-tools.fulder.dev/pki_tools/types/#subject)
    containing all the
    attributes present in
    [RFC5280#Section-4.1.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4)

    Arguments:
        cert -- The certificate to check revocation for. Can either be
        a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        or a
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        string
    Returns:
        A [types.Subject](https://pki-tools.fulder.dev/pki_tools/types/#subject)
        with all the available attributes
    """
    if types._is_pem_str(cert):
        cert = cert_from_pem(cert)

    cert_dict = defaultdict(set)
    for attribute in cert.subject:
        for att in cert.subject.get_attributes_for_oid(attribute.oid):
            cert_dict[att.oid.dotted_string].add(att.value)

    return types.Subject(**cert_dict)


def get_cert_serial(cert: x509.Certificate) -> str:
    """
    Parses the certificate serial into hex format

    Args:
        cert: A
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)

    Returns:
        String representing the hex value of the certificate serial number
    """
    serial = cert.serial_number
    hex_serial = format(serial, "x").zfill(32)
    return hex_serial


@lru_cache(maxsize=None)
def _get_ca_chain_from_uri(
    chain_uri: str, cache_ttl: int = None
) -> (List)[x509.Certificate]:
    ret = requests.get(chain_uri)

    if ret.status_code != 200:
        logger.bind(status=ret.status_code).error(
            "Failed to fetch issuer from URI"
        )
        raise exceptions.OcspIssuerFetchFailure(
            f"Issuer URI fetch failed. Status: {ret.status_code}"
        )

    return x509.load_pem_x509_certificates(ret.content)


def _get_issuer_from_chain(
    chain: List[x509.Certificate], cert: x509.Certificate
):
    for next_chain_cert in chain:
        cert_subject = cert.issuer.rfc4514_string()
        log = logger.bind(subject=cert_subject)
        if cert_subject == next_chain_cert.subject.rfc4514_string():
            log.debug("Found issuer cert in chain")
            return next_chain_cert

    raise exceptions.CertIssuerMissingInChain()
