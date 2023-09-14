from cryptography import x509
from . import ocsp
from . import crl


class Error(Exception):
    pass


class ExtensionMissing(Error):
    pass


class Revoked(Error):
    pass


class CertLoadError(Error):
    pass


def cert_from_pem(cert_pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(cert_pem.encode())
    except ValueError as e:
        raise CertLoadError(e)
