import base64
import binascii
import hashlib

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import (
    Encoding,
    PublicFormat,
)
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


def _is_revoked_multiple_issuers(
    cert: [x509.Certificate, types.PemCert],
    cert_issuer: types.Chain,
    ocsp_issuer: types.Chain,
):
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

            return _check_ocsp_status(aia_exs, req_path, cert, ocsp_issuer)
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


def _construct_req_path(cert, issuer_cert, alg):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, alg)
    req = builder.build()
    return base64.b64encode(
        req.public_bytes(serialization.Encoding.DER)
    ).decode()


def _check_ocsp_status(
    aia_exs, req_path, cert: x509.Certificate, issuer_chain: types.Chain
):
    log = logger.bind(serial=pki_tools.get_cert_serial(cert))

    for aia_ex in aia_exs.value:
        if aia_ex.access_method == x509.AuthorityInformationAccessOID.OCSP:
            server = aia_ex.access_location.value

            ocsp_res = _get_ocsp_status(f"{server}/{req_path}")

            _verify_ocsp_signature(ocsp_res, issuer_chain)

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


def _verify_ocsp_signature(
    ocsp_response: OCSPResponse, issuer_chain: types.Chain
):
    ocsp_response_key_hash = binascii.hexlify(
        ocsp_response.responder_key_hash
    ).decode()

    for issuer_cert in issuer_chain.certificates:
        hash_algorithm = hashlib.new(ocsp_response.hash_algorithm.name)

        der_key = issuer_cert.public_key().public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.PKCS1,
        )
        hash_algorithm.update(der_key)
        cert_public_hash = hash_algorithm.hexdigest()

        if cert_public_hash == ocsp_response_key_hash:
            break
    else:
        raise exceptions.Error("Couldn't find ocsp response issuer")

    pki_tools.verify_signature(ocsp_response, issuer_cert)
