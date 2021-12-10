import requests
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID


class Error(Exception):
    pass


class CrlFetchFailure(Error):
    pass


class CrlLoadError(Error):
    pass


class Revoked(Error):
    pass


def check_revoked(cert_pem: str, require_extension=True):
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    ext = cert.extensions
    try:
        crl_ex = ext.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS,
        )

        for dist_point in crl_ex.value:
            for full_name in dist_point.full_name:
                crl_url = full_name.value

                crl = _get_crl_from_url(crl_url)

                r = crl.get_revoked_certificate_by_serial_number(
                    cert.serial_number,
                )
                if r is not None:
                    err = f"Certificate with serial: {cert.serial_number} " \
                          f"is revoked since: {r.revocation_date}"
                    raise Revoked(err)
    except ExtensionNotFound:
        if require_extension:
            raise Revoked("CRL Distribution Points extension not found")


def _get_crl_from_url(crl_url):
    ret = requests.get(crl_url)

    if ret.status_code != 200:
        raise CrlFetchFailure

    crl_data = ret.content
    return _crl_data_to_crypto(crl_data)


def _crl_data_to_crypto(crl_data):
    try:
        return x509.load_der_x509_crl(crl_data)
    except Exception:
        pass

    try:
        return x509.load_pem_x509_crl(crl_data)
    except ValueError as e:
        raise CrlLoadError(e)
