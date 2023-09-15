import re
from typing import NewType

PemCert = NewType("PemCert", str)
Uri = NewType("Uri", str)

PEM_REGEX = re.compile(r"-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+")
URI_REGEX = re.compile(r"https*://.*")


def _is_uri(check):
    return _check_str(URI_REGEX, check)


def _is_pem_str(check):
    return _check_str(PEM_REGEX, check)


def _check_str(pattern, check):
    if not isinstance(check, str):
        return False

    return re.match(pattern, check)
