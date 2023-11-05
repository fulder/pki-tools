import datetime
import os
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

import pki_tools
from pki_tools.exceptions import (
    CertLoadError,
    Error,
    OcspInvalidResponseStatus,
)
from pki_tools import (
    is_revoked, Certificate,
)

from conftest import (
    _create_mocked_ocsp_response,
    _create_cert,
    _create_crl,
)
from pki_tools.types import Chain


def test_is_revoked_ocsp_good_status(
    mocked_requests_get, cert, key_pair, chain
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

    assert not is_revoked(cert, chain)

def test_is_revoked_ocsp_revoked_status(
    mocked_requests_get, cert, key_pair, chain
):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert,
        key_pair,
        status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=datetime.datetime.now(),
    )

    assert is_revoked(cert, chain)


def test_is_revoked_ocsp_error(
    mocked_requests_get,
    chain,
    key_pair,
    cert,
    mocker,
):
    crl = _create_crl(key_pair, [], cert)
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    res = mocker.MagicMock()
    res.status_code = 200
    res.content = crl_der

    mocked_requests_get.side_effect = [
        OcspInvalidResponseStatus,
        OcspInvalidResponseStatus,
        OcspInvalidResponseStatus,
        OcspInvalidResponseStatus,
        OcspInvalidResponseStatus,
        res,
    ]

    assert not is_revoked(cert, chain)


def test_is_revoked_crl_not_revoked(key_pair, mocked_requests_get):
    crypto_cert = _create_cert(key_pair, add_aia_extension=False)
    cert = Certificate.from_cryptography(crypto_cert)

    crl = _create_crl(key_pair, [], cert)
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl_der

    assert not is_revoked(cert, Chain.from_cryptography([crypto_cert]))


def test_is_revoked_crl_revoked(mocked_requests_get, key_pair):
    crypto_cert = _create_cert(key_pair, add_aia_extension=False)
    cert = Certificate.from_cryptography(crypto_cert)

    crl = _create_crl(key_pair, [cert.serial_number], cert)
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl_der

    assert is_revoked(cert, Chain.from_cryptography([crypto_cert]))


def test_is_revoked_missing_extensions(key_pair, chain):
    crypto_cert = _create_cert(
        key_pair, add_crl_extension=False, add_aia_extension=False
    )
    cert = Certificate.from_cryptography(crypto_cert)

    with pytest.raises(Error):
        is_revoked(cert, chain)


