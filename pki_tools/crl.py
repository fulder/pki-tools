from loguru import logger

from pki_tools.types.extensions import UniformResourceIdentifier
from pki_tools.types.chain import Chain
from pki_tools.types.certificate import Certificate
from pki_tools.exceptions import (
    ExtensionMissing,
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
            crl = CertificateRevocationList.from_uri(
                uri, cache_time_seconds=crl_cache_seconds
            )

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
