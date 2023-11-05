import base64
import hashlib

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

from pki_tools.types.chain import Chain
from pki_tools.types.certificate import Certificate
from pki_tools.utils import HTTPX_CLIENT, verify_signature
from pki_tools.exceptions import (
    ExtensionMissing,
    OcspInvalidResponseStatus,
    OcspFetchFailure,
    Error,
)
from pki_tools.types.utils import _byte_to_hex

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

    try:
        aia_exs = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        )
    except ExtensionNotFound:
        log.debug("OCSP extension missing")
        raise ExtensionMissing()

    for i, alg in enumerate(OCSP_ALGORITHMS_TO_CHECK):
        try:
            req_path = _construct_req_path(cert, issuer, alg)

            return _check_ocsp_status(aia_exs, req_path, cert, ocsp_issuer)
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
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, alg)
    req = builder.build()
    return base64.b64encode(
        req.public_bytes(serialization.Encoding.DER)
    ).decode()


def _check_ocsp_status(
    aia_exs, req_path, cert: Certificate, issuer_chain: Chain
):
    log = logger.bind(serial=cert.hex_serial)

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
    if ocsp_res.response_status != OCSPResponseStatus.SUCCESSFUL:
        log.bind(res=ocsp_res.response_status.name).debug(
            "Invalid OCSP response"
        )
        raise OcspInvalidResponseStatus(
            f"Invalid OCSP Response status: {ocsp_res.response_status}"
        )

    return ocsp_res


def _verify_ocsp_signature(ocsp_response: OCSPResponse, issuer_chain: Chain):
    try:
        ocsp_response_key_hash = _byte_to_hex(ocsp_response.issuer_key_hash)
    except Exception as e:
        logger.bind(
            exceptionType=type(e),
            exception=str(e),
            issuerHash=ocsp_response.issuer_key_hash,
        ).error("Couldn't convert issuer key hash to hex")
        raise

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
        logger.error("Couldn't find OCSP response issuer")
        raise Error("Couldn't find OCSP response issuer")

    verify_signature(ocsp_response, issuer_cert)
