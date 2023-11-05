import base64

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
from loguru import logger

from pki_tools.types.chain import Chain
from pki_tools.types.certificate import Certificate
from pki_tools.utils import HTTPX_CLIENT, verify_signature
from pki_tools.exceptions import (
    ExtensionMissing,
    OcspInvalidResponseStatus,
    OcspFetchFailure,
    Error,
)
from pki_tools.types.extensions import AuthorityInformationAccess
from pki_tools.types.ocsp import OCSPResponse

OCSP_ALGORITHMS_TO_CHECK = [SHA256(), SHA1(), SHA512(), SHA224(), SHA384()]


def _is_revoked_multiple_issuers(
    cert: Certificate,
    cert_issuer: Chain,
    ocsp_issuer: Chain,
):
    cert_issuer.check_chain()
    ocsp_issuer.check_chain()

    issuer = cert_issuer.get_issuer(cert)

    log = logger.bind(
        cert=cert.pem_string,
        serial=cert.serial_number,
    )

    if cert.extensions.authority_information_access is None:
        log.debug("OCSP extension missing")
        raise ExtensionMissing()

    for i, alg in enumerate(OCSP_ALGORITHMS_TO_CHECK):
        try:
            req_path = _construct_req_path(cert, issuer, alg)

            return _check_ocsp_status(
                cert.extensions.authority_information_access,
                req_path,
                cert,
                ocsp_issuer,
            )
        except OcspInvalidResponseStatus:
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
    cert = cert._x509_obj
    issuer_cert = issuer_cert._x509_obj
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, alg)
    req = builder.build()
    return base64.b64encode(
        req.public_bytes(serialization.Encoding.DER)
    ).decode()


def _check_ocsp_status(
    aia: AuthorityInformationAccess,
    req_path,
    cert: Certificate,
    issuer_chain: Chain,
):
    log = logger.bind(serial=cert.hex_serial)

    checked_status = False
    for access_description in aia:
        if access_description.access_method != "OCSP":
            continue

        checked_status = True

        server = access_description.access_location

        ocsp_res = _get_ocsp_status(f"{server}/{req_path}")

        _verify_ocsp_signature(ocsp_res, issuer_chain)

        if ocsp_res.is_revoked:
            log.bind(
                date=str(ocsp_res._x509_obj.revocation_time),
            ).debug("Certificate revoked")
            return True

    if not checked_status:
        raise ExtensionMissing()

    log.debug("Certificate valid")
    return False


def _get_ocsp_status(uri) -> OCSPResponse:
    ret = HTTPX_CLIENT.get(
        uri, headers={"Content-Type": "application/ocsp-request"}
    )

    log = logger.bind(status=ret.status_code)
    if ret.status_code != 200:
        log.error("OCSP status fetch failed")
        raise OcspFetchFailure(
            f"Unexpected response status code: {ret.status_code}"
        )

    ocsp_res = ocsp.load_der_ocsp_response(ret.content)
    ocsp_res = OCSPResponse.from_cryptography(ocsp_res)

    if not ocsp_res.is_successful:
        log.bind(res=ocsp_res.response_status).debug("Invalid OCSP response")
        raise OcspInvalidResponseStatus(
            f"Invalid OCSP Response status: {ocsp_res.response_status}"
        )

    return ocsp_res


def _verify_ocsp_signature(ocsp_response: OCSPResponse, issuer_chain: Chain):
    for issuer_cert in issuer_chain.certificates:
        der_key = issuer_cert.public_key.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.PKCS1,
        )
        cert_public_hash = ocsp_response.hash_with_alg(der_key)

        if cert_public_hash == ocsp_response.issuer_key_hash:
            break
    else:
        logger.error("Couldn't find OCSP response issuer")
        raise Error("Couldn't find OCSP response issuer")

    verify_signature(ocsp_response, issuer_cert)
