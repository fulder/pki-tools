import base64
import time
from functools import lru_cache

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import (
    SHA256,
    SHA1,
    SHA512,
    SHA384,
    SHA224,
)
from cryptography.x509 import ocsp
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPResponse,
    OCSPResponseStatus,
)
from cryptography.x509.oid import ExtensionOID
from loguru import logger

import pki_tools
from pki_tools import exceptions, types

OCSP_ALGORITHMS_TO_CHECK = [SHA256(), SHA1(), SHA512(), SHA224(), SHA384()]


@lru_cache(maxsize=None)
def _get_issuer_from_uri(issuer_uri, cache_ttl=None):
    del cache_ttl

    ret = requests.get(issuer_uri)

    if ret.status_code != 200:
        raise exceptions.OcspIssuerFetchFailure(
            f"Issuer URI fetch failed. Status: {ret.status_code}"
        )

    return pki_tools.cert_from_pem(ret.text)


def is_revoked(
    cert: [x509.Certificate, types.PemCert],
    issuer_cert: [x509.Certificate, types.PemCert, types.OcspIssuerUri],
) -> bool:
    """
    Checks if a certificate is revoked using the OCSP extension.

    Arguments:
        cert -- The certificate to check revocation for. Can either be
        a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
        or a
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        string
        issuer_cert -- The issuer of the `cert`. Can be a
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate),
        a [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
        string or
        [types.OcspIssuerUri](https://pki-tools.fulder.dev/pki_tools/types/#ocspissueruri)
        including the URI to the
        issuer public cert
    Returns:
        True if the certificate is revoked, False otherwise
    Raises:
        [exceptions.ExtensionMissing](https://pki-tools.fulder.dev/pki_tools/exceptions/#extensionmissing)
        -- When OCSP extension is missing

        [exceptions.OcspFetchFailure](https://pki-tools.fulder.dev/pki_tools/exceptions/#ocspfetchfailure)
        -- When OCSP fails getting response from the server

        [exceptions.OcspInvalidResponseStatus](https://pki-tools.fulder.dev/pki_tools/exceptions/#ocspinvalidresponsestatus)
        -- When OCSP returns invalid response status

        [exceptions.OcspIssuerFetchFailure](https://pki-tools.fulder.dev/pki_tools/exceptions/#ocspissuerfetchfailure)
        -- When `issuer_cert` is of
        [types.OcspIssuerUri](https://pki-tools.fulder.dev/pki_tools/types/#ocspissueruri)
        type and fetching the public certificate fails
    """
    if types._is_pem_str(cert):
        cert = pki_tools.cert_from_pem(cert)

    if types._is_pem_str(issuer_cert):
        issuer_cert = pki_tools.cert_from_pem(issuer_cert)
    elif isinstance(issuer_cert, types.OcspIssuerUri):
        cache_ttl = round(time.time() / issuer_cert.cache_time_seconds)
        issuer_cert = _get_issuer_from_uri(
            issuer_cert.uri, cache_ttl=cache_ttl
        )

    try:
        aia_exs = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        )
    except ExtensionNotFound:
        raise exceptions.ExtensionMissing()

    for i, alg in enumerate(OCSP_ALGORITHMS_TO_CHECK):
        try:
            req_path = _construct_req_path(cert, issuer_cert, alg)

            return _check_ocsp_status(aia_exs, req_path, cert)
        except exceptions.OcspInvalidResponseStatus:
            logger.debug(f"OCSP check with: {alg.name} failed, trying another")
            if i + 1 == len(OCSP_ALGORITHMS_TO_CHECK):
                raise

    return False


def _construct_req_path(cert, issuer_cert, alg):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, alg)
    req = builder.build()
    return base64.b64encode(
        req.public_bytes(serialization.Encoding.DER)
    ).decode()


def _check_ocsp_status(aia_exs, req_path, cert):
    for aia_ex in aia_exs.value:
        if aia_ex.access_method == x509.AuthorityInformationAccessOID.OCSP:
            server = aia_ex.access_location.value

            ocsp_res = _get_ocsp_status(f"{server}/{req_path}")

            if ocsp_res.certificate_status == OCSPCertStatus.REVOKED:
                logger.info(
                    f"Certificate with serial: {cert.serial_number} "
                    f"is revoked since: {ocsp_res.revocation_time}"
                )
                return True
    return False


def _get_ocsp_status(uri) -> OCSPResponse:
    ret = requests.get(
        uri, headers={"Content-Type": "application/ocsp-request"}
    )

    if ret.status_code != 200:
        raise exceptions.OcspFetchFailure(
            f"Unexpected response status code: {ret.status_code}"
        )

    ocsp_res = ocsp.load_der_ocsp_response(ret.content)
    if ocsp_res.response_status != OCSPResponseStatus.SUCCESSFUL:
        raise exceptions.OcspInvalidResponseStatus(
            f"Invalid OCSP Response status: {ocsp_res.response_status}"
        )

    return ocsp_res
