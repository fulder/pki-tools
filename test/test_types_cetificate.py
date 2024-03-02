import os

import pytest
from cryptography import x509
from cryptography.hazmat._oid import NameOID

from conftest import TEST_SUBJECT, CURRENT_DIR
from pki_tools import Certificate, CertLoadError
from pki_tools.types import RSAKeyPair


def test_certificate_subject_to_crypto_name():
    name = TEST_SUBJECT.to_crypto_name()

    assert name == x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, TEST_SUBJECT.c[0]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, TEST_SUBJECT.o[0]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, TEST_SUBJECT.o[1]),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, TEST_SUBJECT.ou[0]
            ),
            x509.NameAttribute(NameOID.DN_QUALIFIER, TEST_SUBJECT.dnq[0]),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, TEST_SUBJECT.s[0]
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, TEST_SUBJECT.cn[0]),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, TEST_SUBJECT.serial[0]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, TEST_SUBJECT.ln[0]),
            x509.NameAttribute(NameOID.TITLE, TEST_SUBJECT.t[0]),
            x509.NameAttribute(NameOID.SURNAME, TEST_SUBJECT.sn[0]),
            x509.NameAttribute(NameOID.GIVEN_NAME, TEST_SUBJECT.gn[0]),
            x509.NameAttribute(NameOID.INITIALS, TEST_SUBJECT.i[0]),
            x509.NameAttribute(NameOID.PSEUDONYM, TEST_SUBJECT.p[0]),
            x509.NameAttribute(
                NameOID.GENERATION_QUALIFIER, TEST_SUBJECT.gq[0]
            ),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, TEST_SUBJECT.dc[0]),
        ]
    )


def test_certificate_from_to_cryptography(crypto_cert, cert_pem_string):
    cert = Certificate.from_cryptography(crypto_cert)

    cert.sign(RSAKeyPair.generate(), cert.signature_algorithm)
    created_crypto_cert = cert._to_cryptography()

    dict1 = cert._string_dict()
    dict2 = Certificate.from_cryptography(created_crypto_cert)._string_dict()

    del dict1["Certificate"]["Signature Value"]
    del dict2["Certificate"]["Signature Value"]
    remove_ext = ["Serial Number", "Validity", "Subject Public Key Info"]
    for ext in remove_ext:
        del dict1["Certificate"]["TbsCertificate"][ext]
        del dict2["Certificate"]["TbsCertificate"][ext]

    assert dict1 == dict2

    # Test getting cert properties
    assert cert.digest() != ""
    assert cert.hex_serial != ""


def test_certificate_from_pem_string_with_subject_directory_attributes(
    cert_with_subject_directory_attributes,
):
    Certificate.from_pem_string(cert_with_subject_directory_attributes)


def test_certificate_from_pem_string_invalid_data():
    with pytest.raises(CertLoadError):
        Certificate.from_pem_string("BAD_PEM_DATA")


def test_certificate_from_pem_string_with_space(cert_pem_string):
    Certificate.from_pem_string("\n\n" + cert_pem_string + "\n")


def test_certificate_save_and_read_file(cert_pem_string):
    cert = Certificate.from_pem_string(cert_pem_string)

    file_path = os.path.join(CURRENT_DIR, "tmp.pem")
    cert.to_file(file_path)

    new_cert = Certificate.from_file(file_path)

    os.remove(file_path)

    assert cert.pem_string == new_cert.pem_string


def test_certificate_to_cryptography(cert, key_pair):
    cert._to_cryptography()
