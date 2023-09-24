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



def is_revoked_multiple_issuers(
    cert: [x509.Certificate, types.PemCert],
    cert_issuer: types.Chain,
    ocsp_issuer: types.Chain,
):
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
    cert_issuer.check_chain()
    ocsp_issuer.check_chain()

    if types._is_pem_str(cert):
        cert = pki_tools.cert_from_pem(cert)

    issuer = cert_issuer.get_issuer(cert)

    log = logger.bind(
        cert=pki_tools.pem_from_cert(cert),
        serial=pki_tools.get_cert_serial(cert),
    )

    try:
        aia_exs = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        )
    except ExtensionNotFound:
        log.debug("OCSP extension missing")
        raise exceptions.ExtensionMissing()

    for i, alg in enumerate(OCSP_ALGORITHMS_TO_CHECK):
        try:
            req_path = _construct_req_path(cert, issuer, alg)

            return _check_ocsp_status(aia_exs, req_path, cert)
        except exceptions.OcspInvalidResponseStatus:
            log.bind(alg=alg.name).debug(
                "OCSP check failed, trying another algorithm"
            )
            if i + 1 == len(OCSP_ALGORITHMS_TO_CHECK):
                log.bind(
                    algs=[alg.name for alg in OCSP_ALGORITHMS_TO_CHECK]
                ).debug("All algorithms check failed")
                raise

    return False


def is_revoked(
    cert: [x509.Certificate, types.PemCert],
    chain: types.Chain
) -> bool:
    return is_revoked_multiple_issuers(cert, chain, chain)


def _construct_req_path(cert, issuer_cert, alg):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, alg)
    req = builder.build()
    return base64.b64encode(
        req.public_bytes(serialization.Encoding.DER)
    ).decode()


def _check_ocsp_status(aia_exs, req_path, cert):
    log = logger.bind(serial=pki_tools.get_cert_serial(cert))

    for aia_ex in aia_exs.value:
        if aia_ex.access_method == x509.AuthorityInformationAccessOID.OCSP:
            server = aia_ex.access_location.value

            ocsp_res = _get_ocsp_status(f"{server}/{req_path}")

            if ocsp_res.certificate_status == OCSPCertStatus.REVOKED:
                log.bind(
                    date=str(ocsp_res.revocation_time),
                ).debug("Certificate revoked")
                return True

    log.debug("Certificate valid")
    return False


def _get_ocsp_status(uri) -> OCSPResponse:
    ret = requests.get(
        uri, headers={"Content-Type": "application/ocsp-request"}
    )

    log = logger.bind(status=ret.status_code)
    if ret.status_code != 200:
        log.error("OCSP status fetch failed")
        raise exceptions.OcspFetchFailure(
            f"Unexpected response status code: {ret.status_code}"
        )

    ocsp_res = ocsp.load_der_ocsp_response(ret.content)
    if ocsp_res.response_status != OCSPResponseStatus.SUCCESSFUL:
        log.bind(res=ocsp_res.response_status.name).debug(
            "Invalid OCSP response"
        )
        raise exceptions.OcspInvalidResponseStatus(
            f"Invalid OCSP Response status: {ocsp_res.response_status}"
        )

    return ocsp_res
