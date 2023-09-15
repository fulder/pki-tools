import re
from typing import NewType

from pydantic import constr, BaseModel

PemCert = NewType("PemCert", str)

PEM_REGEX = re.compile(r"-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+")


class OcspIssuerUri(BaseModel):
    uri: constr(pattern=r"https*://.*")
    cache_time_seconds: int = 3600


def _is_pem_str(check):
    return _check_str(PEM_REGEX, check)


def _check_str(pattern, check):
    if not isinstance(check, str):
        return False

    return re.match(pattern, check)
