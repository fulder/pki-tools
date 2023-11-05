import time
from functools import lru_cache
from typing import Union

from cryptography import x509
from loguru import logger


from pki_tools.utils import HTTPX_CLIENT, verify_signature

from pki_tools.types.chain import Chain

from pki_tools.types.certificate import Certificate

from pki_tools.exceptions import ExtensionMissing, CrlFetchFailure, CrlLoadError


def _is_revoked(
    cert: Certificate,
    crl_issuer: Chain,
    crl_cache_seconds: int = 3600,
) -> bool:
    crl_issuer.check_chain()
    logger.debug("CRL issuer chain valid")

    log = logger.bind(
        cert=cert.pem_string,
        serial=cert.hex_serial,
    )

    if cert.extensions.crl_distribution_points is None:
        log.debug("CRL extension missing")
        raise ExtensionMissing()

    http_dist = False
    for dist_point in cert.extensions.crl_distribution_points:
        if dist_point.full_name is None:
            continue

        for full_name in dist_point.full_name:
            if "http" not in full_name:
                continue

            http_dist = True
            cache_ttl = round(time.time() / crl_cache_seconds)
            crl = _get_crl_from_url(full_name, cache_ttl=cache_ttl)

            issuer = crl_issuer.get_issuer(crl)

            verify_signature(crl, issuer)
            logger.debug("CRL signature valid")

            r = crl.get_revoked_certificate_by_serial_number(
                cert.serial_number,
            )
            if r is not None:
                log.bind(date=str(r.revocation_date)).debug(
                    "Certificate revoked"
                )
                return True

    if not http_dist:
        log.debug("CRL missing URI")
        raise ExtensionMissing()

    log.debug("Certificate valid")
    return False


@lru_cache(maxsize=None)
def _get_crl_from_url(crl_url, cache_ttl=None):
    ret = HTTPX_CLIENT.get(crl_url)

    if ret.status_code != 200:
        logger.bind(
            status=ret.status_code,
            url=crl_url,
        ).error("Failed to fetch CRL from URL")
        raise CrlFetchFailure()

    crl_data = ret.content
    return _crl_data_to_crypto(crl_data)


def _crl_data_to_crypto(crl_data):
    try:
        return x509.load_der_x509_crl(crl_data)
    except (TypeError, ValueError):
        pass

    try:
        return x509.load_pem_x509_crl(crl_data)
    except TypeError as e:
        logger.bind(crl=crl_data).error("Failed to load CRL")
        raise CrlLoadError(e) from None
