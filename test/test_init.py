import datetime
import os
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

from pki_tools.exceptions import (
    CertLoadError,
    Error,
    OcspInvalidResponseStatus,
)
from pki_tools import (
    cert_from_pem,
    is_revoked,
    save_to_file,
    read_from_file,
    parse_subject,
    types,
)
from conftest import (
    _create_mocked_ocsp_response,
    _create_cert,
    _create_crl,
    CURRENT_DIR,
    TEST_SUBJECT,
)


def test_cert_load_error():
    with pytest.raises(CertLoadError):
        cert_from_pem("BAD_PEM_DATA")


def test_is_revoked_pem_ocsp(
    cert_pem_string, mocked_requests_get, cert, key_pair
):
    correct_res = MagicMock()
    correct_res.status_code = 200
    correct_res.content = _create_mocked_ocsp_response(cert, key_pair)

    mocked_requests_get.side_effect = [
        OcspInvalidResponseStatus,
        OcspInvalidResponseStatus,
        OcspInvalidResponseStatus,
        correct_res,
        OcspInvalidResponseStatus,
    ]

    assert not is_revoked(cert_pem_string, types.PemCert(cert_pem_string))


def test_is_revoked_pem_failure(
    cert_pem_string,
    mocked_requests_get,
):
    mocked_requests_get.side_effect = OcspInvalidResponseStatus

    with pytest.raises(OcspInvalidResponseStatus):
        assert is_revoked(cert_pem_string, types.PemCert(cert_pem_string))


def test_is_revoked_cert_ocsp(mocked_requests_get, cert, key_pair):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert, key_pair
    )

    assert not is_revoked(cert, cert)


def test_is_revoked_pem_with_spaces(
    cert_pem_string, mocked_requests_get, cert, key_pair
):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert, key_pair
    )

    assert not is_revoked(
        "\n\n" + cert_pem_string + "\n", types.PemCert(cert_pem_string)
    )


def test_is_revoked_pem_crl(key_pair, mocked_requests_get):
    cert = _create_cert(key_pair, add_aia_extension=False)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    crl = _create_crl(key_pair, [])
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl_der

    assert not is_revoked(cert_pem, cert_pem)


def test_is_revoked_pem_ocsp_revoked(
    cert_pem_string, mocked_requests_get, cert, key_pair
):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert,
        key_pair,
        status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=datetime.datetime.now(),
    )

    assert is_revoked(cert_pem_string, cert_pem_string)


def test_is_revoked_pem_crl_revoked(mocked_requests_get, key_pair):
    cert = _create_cert(key_pair, add_aia_extension=False)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    crl = _create_crl(key_pair, [cert.serial_number])
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl_der

    assert is_revoked(cert_pem, cert_pem)


def test_is_revoked_missing_extensions(key_pair):
    cert = _create_cert(
        key_pair, add_crl_extension=False, add_aia_extension=False
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    with pytest.raises(Error):
        is_revoked(cert_pem)


def test_save_and_read_file(cert):
    file_path = os.path.join(CURRENT_DIR, "tmp.pem")
    save_to_file([cert], file_path)
    new_pem = read_from_file(file_path)

    os.remove(file_path)

    assert cert == new_pem


def test_parse_subject(cert):
    subj = parse_subject(cert)

    # Ignore multi value order
    assert set(subj.o) == set(TEST_SUBJECT.o)
    subj.o = TEST_SUBJECT.o

    assert subj == TEST_SUBJECT
