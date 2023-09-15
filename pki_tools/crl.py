import time
from functools import lru_cache
from typing import Union

import requests
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID
from loguru import logger

from pki_tools import exceptions
from pki_tools import types
from pki_tools import utils


def is_revoked(
    cert: Union[x509.Certificate, types.PemCert], crl_cache_seconds: int = 3600
) -> bool:
    if types._is_pem_str(cert):
        cert = utils.cert_from_pem(cert)

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

                r = crl.get_revoked_certificate_by_serial_number(
                    cert.serial_number,
                )
                if r is not None:
                    logger.info(
                        f"Certificate with serial: {cert.serial_number} "
                        f"is revoked since: {r.revocation_date}"
                    )
                    return True
    except ExtensionNotFound:
        raise exceptions.ExtensionMissing()
    return False


@lru_cache(maxsize=None)
def _get_crl_from_url(crl_url, cache_ttl=None):
    del cache_ttl

    ret = requests.get(crl_url)

    if ret.status_code != 200:
        raise exceptions.CrlFetchFailure

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
        raise exceptions.CrlLoadError(e) from None
