import base64

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPResponse,
    OCSPResponseStatus,
)
from cryptography.x509.oid import ExtensionOID
from loguru import logger

from pki_tools import exceptions
from pki_tools import utils
from pki_tools import types


def _get_issuer_from_uri(issuer_uri):
    ret = requests.get(issuer_uri)

    if ret.status_code != 200:
        raise exceptions.OcspFetchFailure(
            f"Issuer URI fetch failed. Status: {ret.status_code}"
        )

    return utils.cert_from_pem(ret.text)


def is_revoked(
    cert: [x509.Certificate, types.PemCert],
    issuer_cert: [x509.Certificate, types.PemCert, types.Uri],
) -> bool:
    if types._is_pem_str(cert):
        cert = utils.cert_from_pem(cert)

    if types._is_pem_str(issuer_cert):
        issuer_cert = utils.cert_from_pem(issuer_cert)
    elif types._is_uri(issuer_cert):
        issuer_cert = _get_issuer_from_uri(issuer_cert)

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, SHA256())
    req = builder.build()
    req_path = base64.b64encode(
        req.public_bytes(serialization.Encoding.DER)
    ).decode("ascii")

    try:
        aia_exs = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        )

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
    except ExtensionNotFound:
        raise exceptions.ExtensionMissing()
    return False


def _get_ocsp_status(uri) -> OCSPResponse:
    ret = requests.get(uri)

    if ret.status_code != 200:
        raise exceptions.OcspFetchFailure(
            f"Unexpected response status code: {ret.status_code}"
        )

    ocsp_res = ocsp.load_der_ocsp_response(ret.content)
    if ocsp_res.response_status != OCSPResponseStatus.SUCCESSFUL:
        raise exceptions.OcspFetchFailure(
            f"Invalid OCSP Response status: {ocsp_res.response_status}"
        )

    return ocsp_res
