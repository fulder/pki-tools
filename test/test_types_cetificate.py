import datetime
import os

import pytest
from cryptography import x509
from cryptography.hazmat._oid import NameOID

from conftest import TEST_SUBJECT, CURRENT_DIR
from pki_tools.types.signature_algorithm import SHA256
from pki_tools.types.certificate import Certificate, Name, Validity
from pki_tools.exceptions import LoadError
from pki_tools.types import RSAKeyPair


def test_certificate_subject_to_crypto_name():
    name = TEST_SUBJECT._to_cryptography()

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

    del dict1["Signature Value"]
    del dict2["Signature Value"]
    remove_ext = ["Serial Number", "Validity", "Subject Public Key Info"]
    for ext in remove_ext:
        del dict1[ext]
        del dict2[ext]

    assert dict1 == dict2

    # Test getting cert properties
    assert cert.digest() != ""
    assert cert.hex_serial != ""
    assert cert.sign_alg_oid_name != ""
    assert "-----BEGIN PUBLIC KEY-----" in cert.public_key.decode()
    assert cert.tbs_bytes != ""
    assert "-----BEGIN CERTIFICATE-----" in cert.pem_bytes.decode()
    assert "-----BEGIN CERTIFICATE-----" in cert.pem_string
    assert cert.der_bytes != ""


def test_certificate_from_pem_string_with_subject_directory_attributes(
    cert_with_subject_directory_attributes,
):
    Certificate.from_pem_string(cert_with_subject_directory_attributes)


def test_certificate_from_pem_string_invalid_data():
    with pytest.raises(LoadError):
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


def test_certificate_sign_another_key(cert):
    signing_key = RSAKeyPair.generate()
    csr_key = RSAKeyPair.generate()

    cert.sign(
        signing_key, cert.signature_algorithm, req_key=csr_key.public_key
    )

    rel = cert.subject_public_key_info.algorithm._string_dict()
    exp = csr_key.public_key._string_dict()
    assert rel == exp


def test_certificate_from_to_der(cert):
    der_bytes = cert.der_bytes

    Certificate.from_der_bytes(der_bytes)


def test_certificate_to_from_crypto(key_pair):
    today = datetime.datetime.today()
    one_day = datetime.timedelta(days=1)

    cert = Certificate(
        subject=Name(cn=["subject"]),
        issuer=Name(cn=["issuer"]),
        validity=Validity(not_before=today, not_after=today + one_day),
    )

    cert.sign(key_pair, SHA256)
    crypto_cert = cert._to_cryptography()

    cert2 = Certificate.from_cryptography(crypto_cert)

    assert cert2.subject.cn[0] == "subject"
    assert cert2.issuer.cn[0] == "issuer"
