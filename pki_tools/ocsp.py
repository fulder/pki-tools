import time
from functools import lru_cache

from loguru import logger

from pki_tools.types.chain import Chain
from pki_tools.types.certificate import Certificate
from pki_tools.types.signature_algorithm import HashAlgorithm
from pki_tools.utils import HTTPX_CLIENT
from pki_tools.exceptions import (
    ExtensionMissing,
    OcspInvalidResponseStatus,
    OcspFetchFailure,
    Error,
)
from pki_tools.types.extensions import (
    AuthorityInformationAccess,
    UniformResourceIdentifier,
    AccessDescriptionId,
)
from pki_tools.types.ocsp import OCSPResponse, OCSPRequest

OCSP_ALGORITHMS_TO_CHECK = [
    HashAlgorithm(name="SHA256"),
    HashAlgorithm(name="SHA1"),
    HashAlgorithm(name="SHA512"),
    HashAlgorithm(name="SHA224"),
    HashAlgorithm(name="SHA384"),
]


def _is_revoked_multiple_issuers(
    cert: Certificate,
    cert_issuer: Chain,
    ocsp_issuer: Chain,
    ocsp_res_cache_seconds: int = 3600,
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
                ocsp_res_cache_seconds=ocsp_res_cache_seconds,
            )
        except OcspInvalidResponseStatus:
            log.bind(alg=alg.name.value).debug(
                "OCSP check failed, trying another algorithm"
            )
            if i + 1 == len(OCSP_ALGORITHMS_TO_CHECK):
                log.bind(
                    algs=[alg.name.value for alg in OCSP_ALGORITHMS_TO_CHECK]
                ).debug("All algorithms check failed")
                raise

    return False


def _construct_req_path(cert, issuer_cert, alg):
    req = OCSPRequest(hash_algorithm=alg)
    req.create(cert, issuer_cert)
    return req.request_path


def _check_ocsp_status(
    aia: AuthorityInformationAccess,
    req_path,
    cert: Certificate,
    issuer_chain: Chain,
    ocsp_res_cache_seconds: int = 3600,
):
    log = logger.bind(serial=cert.hex_serial)

    checked_status = False
    for access_description in aia:
        if access_description.access_method != AccessDescriptionId.OCSP:
            logger.trace(
                "Access method is not OCSP, "
                "try checking next access description"
            )
            continue

        if not isinstance(
            access_description.access_location, UniformResourceIdentifier
        ):
            continue

        checked_status = True

        server = access_description.access_location.value

        cache_ttl = round(time.time() / ocsp_res_cache_seconds)
        ocsp_res = _get_ocsp_status(
            f"{server}/{req_path}", cache_ttl=cache_ttl
        )

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


@lru_cache(maxsize=None)
def _get_ocsp_status(uri, cache_ttl=None) -> OCSPResponse:
    ret = HTTPX_CLIENT.get(
        uri, headers={"Content-Type": "application/ocsp-request"}
    )

    log = logger.bind(status=ret.status_code)
    if ret.status_code != 200:
        log.error("OCSP status fetch failed")
        raise OcspFetchFailure(
            f"Unexpected response status code: {ret.status_code}"
        )

    ocsp_res = OCSPResponse.from_der_bytes(ret.content)

    if not ocsp_res.is_successful:
        log.bind(res=ocsp_res.response_status).debug("Invalid OCSP response")
        raise OcspInvalidResponseStatus(
            f"Invalid OCSP Response status: {ocsp_res.response_status}"
        )

    return ocsp_res


def _verify_ocsp_signature(ocsp_response: OCSPResponse, issuer_chain: Chain):
    for issuer_cert in issuer_chain.certificates:
        cert_public_hash = ocsp_response.hash_with_alg(
            issuer_cert.der_public_key
        )

        if cert_public_hash == ocsp_response.issuer_key_hash:
            break
    else:
        logger.error("Couldn't find OCSP response issuer")
        raise Error("Couldn't find OCSP response issuer")

    issuer_cert.verify_signature(ocsp_response)
