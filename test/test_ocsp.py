import pytest

from pki_tools.exceptions import ExtensionMissing, OcspFetchFailure
from pki_tools.ocsp import is_revoked
from conftest import _create_cert


def test_cert_missing_extension(key_pair):
    cert = _create_cert(key_pair, add_aia_extension=False)

    with pytest.raises(ExtensionMissing):
        is_revoked(cert, cert)


def test_ocsp_fetch_error(mocked_requests_get, cert):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(OcspFetchFailure):
        is_revoked(cert, cert)
