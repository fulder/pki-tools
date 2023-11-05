import pytest

from pki_tools import OcspFetchFailure
from pki_tools.ocsp import _is_revoked_multiple_issuers


def test_ocsp_fetch_error(mocked_requests_get, cert, chain):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(OcspFetchFailure):
        _is_revoked_multiple_issuers(cert, chain, chain)
