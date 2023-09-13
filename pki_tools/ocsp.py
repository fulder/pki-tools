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

from . import Error, ExtensionMissing, Revoked, cert_from_pem


class OcspFetchFailure(Error):
    pass


def check_revoked(cert_pem: str, issuer_cert_pem: str):
    cert = cert_from_pem(cert_pem)
    issuer_cert = cert_from_pem(issuer_cert_pem)
    check_revoked_crypto_cert(cert, issuer_cert)


def check_revoked_crypto_cert(
    cert: x509.Certificate, issuer_cert: x509.Certificate
):
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
                    err = (
                        f"Certificate with serial: {cert.serial_number} "
                        f"is revoked since: {ocsp_res.revocation_time}"
                    )
                    raise Revoked(err)
    except ExtensionNotFound:
        raise ExtensionMissing()


def _get_ocsp_status(uri) -> OCSPResponse:
    ret = requests.get(uri)

    if ret.status_code != 200:
        raise OcspFetchFailure(
            f"Unexpected response status code: {ret.status_code}"
        )

    ocsp_res = ocsp.load_der_ocsp_response(ret.content)
    if ocsp_res.response_status != OCSPResponseStatus.SUCCESSFUL:
        raise OcspFetchFailure(
            f"Invalid OCSP Response status: {ocsp_res.response_status}"
        )

    return ocsp_res
