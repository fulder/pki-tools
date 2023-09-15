import pytest

from pki_tools.exceptions import OcspFetchFailure
from pki_tools.ocsp import is_revoked


def test_ocsp_fetch_error(mocked_requests_get, cert):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(OcspFetchFailure):
        is_revoked(cert, cert)
