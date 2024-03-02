import time
from functools import lru_cache

from loguru import logger

from pki_tools.types.extensions import UniformResourceIdentifier
from pki_tools.utils import HTTPX_CLIENT
from pki_tools.types.chain import Chain
from pki_tools.types.certificate import Certificate
from pki_tools.exceptions import (
    ExtensionMissing,
    CrlFetchFailure,
)
from pki_tools.types.crl import CertificateRevocationList


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
            if not isinstance(full_name, UniformResourceIdentifier):
                logger.warning(
                    "CRL Distribution Point is not "
                    "UniformResourceIdentifier"
                )
                continue

            uri = full_name.value

            http_dist = True
            cache_ttl = round(time.time() / crl_cache_seconds)
            crl = _get_crl_from_url(uri, cache_ttl=cache_ttl)

            issuer = crl_issuer.get_issuer(crl)

            issuer.verify_signature(crl)
            logger.debug("CRL signature valid")

            if (r := crl.get_revoked(cert.serial_number)) is not None:
                log.bind(date=str(r.date)).debug("Certificate revoked")
                return True

    if not http_dist:
        log.debug("CRL missing URI")
        raise ExtensionMissing()

    log.debug("Certificate valid")
    return False


@lru_cache(maxsize=None)
def _get_crl_from_url(crl_url, cache_ttl=None) -> CertificateRevocationList:
    ret = HTTPX_CLIENT.get(crl_url)

    if ret.status_code != 200:
        logger.bind(
            status=ret.status_code,
            url=crl_url,
        ).error("Failed to fetch CRL from URL")
        raise CrlFetchFailure()

    return CertificateRevocationList.from_bytes(ret.content)
