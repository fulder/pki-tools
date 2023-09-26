import time
from functools import lru_cache
from typing import Union

import requests
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID
from loguru import logger

import pki_tools
from pki_tools import types, exceptions


def _is_revoked(
    cert: Union[x509.Certificate, types.PemCert],
    crl_issuer: types.Chain,
    crl_cache_seconds: int = 3600,
) -> bool:
    crl_issuer.check_chain()
    logger.debug("CRL issuer chain valid")

    if types._is_pem_str(cert):
        cert = pki_tools.cert_from_pem(cert)

    log = logger.bind(
        cert=pki_tools.pem_from_cert(cert),
        serial=pki_tools.get_cert_serial(cert),
    )

    ext = cert.extensions
    try:
        crl_ex = ext.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS,
        )

        for dist_point in crl_ex.value:
            for full_name in dist_point.full_name:
                crl_url = full_name.value

                cache_ttl = round(time.time() / crl_cache_seconds)
                crl = _get_crl_from_url(crl_url, cache_ttl=cache_ttl)

                issuer = crl_issuer.get_issuer(crl)

                pki_tools.verify_signature(crl, issuer)
                logger.debug("CRL signature valid")

                r = crl.get_revoked_certificate_by_serial_number(
                    cert.serial_number,
                )
                if r is not None:
                    log.bind(date=str(r.revocation_date)).info(
                        "Certificate revoked"
                    )
                    return True
    except ExtensionNotFound:
        log.debug("CRL extension missing")
        raise exceptions.ExtensionMissing()

    log.info("Certificate valid")
    return False


@lru_cache(maxsize=None)
def _get_crl_from_url(crl_url, cache_ttl=None):
    del cache_ttl

    ret = requests.get(crl_url)

    if ret.status_code != 200:
        logger.bind(
            status=ret.status_code,
            url=crl_url,
        ).error("Failed to fetch CRL from URL")
        raise exceptions.CrlFetchFailure()

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
        raise exceptions.CrlLoadError(e) from None
