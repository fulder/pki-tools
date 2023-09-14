import pytest

from pki_tools.exceptions import CertLoadError
from pki_tools.utils import cert_from_pem


def test_cert_load_error():
    with pytest.raises(CertLoadError):
        cert_from_pem("BAD_PEM_DATA")
