import socket
from urllib.parse import urlparse

from loguru import logger

from pki_tools.types.extensions import UniformResourceIdentifier
from pki_tools.types.chain import Chain
from pki_tools.types.certificate import Certificate
from pki_tools.exceptions import ExtensionMissing, CrlIdpInvalid
from pki_tools.types.crl import CertificateRevocationList


def _compare_cdp_and_idp(
    cdp_uri: str, idp_uri: str, same_crl_domains: list[list[str]] = None
):
    log = logger.bind(
        cdp=cdp_uri,
        idp=idp_uri,
    )

    parsed_cdp = urlparse(cdp_uri)
    parsed_idp = urlparse(idp_uri)

    if (
        parsed_cdp.path.rstrip("/").split("/")[-1]
        != parsed_idp.path.rstrip("/").split("/")[-1]
    ):
        log.warning("CRL IDP path is not the same as cert CDP")
        return False

    if parsed_cdp.scheme != parsed_idp.scheme:
        log.warning("CRL IDP scheme is not the same as cert CDP")
        return False

    if same_crl_domains is not None:
        for domain_list in same_crl_domains:
            if (
                parsed_cdp.hostname in domain_list
                and parsed_idp.hostname in domain_list
            ):
                log.debug(
                    "CRL IDP and cert CDP are considered to be the same domain"
                )
                return True

    if parsed_cdp.hostname != parsed_idp.hostname:
        try:
            cdp_ips = set(socket.gethostbyname_ex(parsed_cdp.hostname)[2])
            idp_ips = set(socket.gethostbyname_ex(parsed_idp.hostname)[2])
        except socket.gaierror:
            log.warning(
                "CRL IDP or cert CDP hostname not resolvable and differ"
            )
            return False

        if not (cdp_ips <= idp_ips or idp_ips <= cdp_ips):
            # Not (All elements of one set are in the other)
            log.bind(
                cdp_ips=",".join(cdp_ips),
                idp_ips=",".join(idp_ips),
            ).warning("CRL IDP hostname is not the same as cert CDP")
            return False

    return True


def _is_revoked(
    cert: Certificate,
    crl_issuer: Chain,
    crl_cache_seconds: int = 3600,
    same_crl_domains: list[list[str]] = None,
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
                log.warning(
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
            log.debug("CRL signature valid")

            if (
                crl.extensions is not None
                and crl.extensions.issuing_distribution_point is not None
                and crl.extensions.issuing_distribution_point.full_name
                is not None
            ):
                log.debug("CRL Issuing Distribution Point extension present")
                full_names = (
                    crl.extensions.issuing_distribution_point.full_name
                )

                for crl_idp in full_names:
                    if _compare_cdp_and_idp(
                        uri, crl_idp.value, same_crl_domains=same_crl_domains
                    ):
                        break
                else:
                    log.error("CRL IDP and cert CDP differ")
                    raise CrlIdpInvalid()

            if (r := crl.get_revoked(cert.serial_number)) is not None:
                log.bind(date=str(r.date)).debug("Certificate revoked")
                return True

    if not http_dist:
        log.debug("CRL missing URI")
        raise ExtensionMissing()

    log.debug("Certificate valid")
    return False
