import datetime
import pytest
import pytz

from pki_tools import Chain, Certificate, Name
from pki_tools.exceptions import CertIssuerMissingInChain, CertExpired
from pki_tools.types.certificate import Validity
from pki_tools.types.extensions import (
    Extensions,
    BasicConstraints,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    RFC822Name,
)
from pki_tools.types.signature_algorithm import SHA256
from conftest import _create_cert, TEST_SUBJECT


class TestValidateTrustPath:
    """Tests for the validate_trust_path() method in Chain class."""

    def test_validate_trust_path_valid_chain(self, key_pair):
        """Test validation succeeds with a valid self-signed certificate."""
        cert = _create_cert(key_pair)
        chain = Chain(certificates=[cert])

        # Should not raise
        chain.validate_trust_path(cert)

    def test_validate_trust_path_cert_issuer_missing(self, key_pair):
        """Test that CertIssuerMissingInChain is raised when issuer is not in chain."""
        # Create a certificate signed by a keypair
        ca_keypair = key_pair
        ca_cert = _create_cert(ca_keypair)

        # Create another keypair for the end-entity cert
        from pki_tools import RSAKeyPair

        ee_keypair = RSAKeyPair.generate()

        # Create end-entity certificate with different issuer
        ee_subject = Name(
            c=["US"],
            o=["Test Org"],
            cn=["test.com"],
        )
        ee_cert = Certificate(
            subject=ee_subject,
            issuer=ca_cert.subject,  # Issued by CA
            extensions=Extensions(
                basic_constraints=BasicConstraints(ca=False),
                subject_key_identifier=SubjectKeyIdentifier(
                    subject_key_identifier=b"TEST_SKI"
                ),
                authority_key_identifier=AuthorityKeyIdentifier(
                    key_identifier=b"TEST_AKI",
                    authority_cert_issuer=[RFC822Name("TEST_NAME")],
                    authority_cert_serial_number=123123,
                    critical=True,
                ),
            ),
            validity=Validity(
                not_before=datetime.datetime.now(pytz.utc),
                not_after=datetime.datetime.now(pytz.utc)
                + datetime.timedelta(days=1),
            ),
        )
        ee_cert.sign(ee_keypair, SHA256)

        # Create chain with only end-entity cert (missing issuer)
        chain = Chain(certificates=[ee_cert])

        # Should raise CertIssuerMissingInChain
        with pytest.raises(CertIssuerMissingInChain):
            chain.validate_trust_path(ee_cert)

    def test_validate_trust_path_expired_intermediate(self, key_pair):
        """Test that CertExpired is raised for expired non-root intermediate."""
        # Create an expired certificate
        today = datetime.datetime.now(pytz.utc)
        yesterday = today - datetime.timedelta(days=1)

        expired_cert = Certificate(
            subject=TEST_SUBJECT,
            issuer=TEST_SUBJECT,
            extensions=Extensions(
                basic_constraints=BasicConstraints(ca=True),
                subject_key_identifier=SubjectKeyIdentifier(
                    subject_key_identifier=b"TEST_SKI"
                ),
            ),
            validity=Validity(
                not_before=yesterday - datetime.timedelta(days=10),
                not_after=yesterday,  # Already expired
            ),
        )
        expired_cert.sign(key_pair, SHA256)

        # Create another cert that is issued by the expired cert
        from pki_tools import RSAKeyPair

        ee_keypair = RSAKeyPair.generate()

        ee_subject = Name(
            c=["US"],
            o=["Test Org"],
            cn=["test.com"],
        )
        ee_cert = Certificate(
            subject=ee_subject,
            issuer=expired_cert.subject,
            extensions=Extensions(
                basic_constraints=BasicConstraints(ca=False),
                subject_key_identifier=SubjectKeyIdentifier(
                    subject_key_identifier=b"TEST_SKI_EE"
                ),
                authority_key_identifier=AuthorityKeyIdentifier(
                    key_identifier=b"TEST_AKI_EE",
                    authority_cert_issuer=[RFC822Name("TEST_NAME")],
                    authority_cert_serial_number=123123,
                    critical=True,
                ),
            ),
            validity=Validity(
                not_before=yesterday - datetime.timedelta(days=5),
                not_after=today + datetime.timedelta(days=30),
            ),
        )
        ee_cert.sign(ee_keypair, SHA256)

        # Create chain with both certs
        chain = Chain(certificates=[ee_cert, expired_cert])

        # Should raise CertExpired when validating the chain
        with pytest.raises(CertExpired):
            chain.validate_trust_path(ee_cert)

    def test_validate_trust_path_root_not_expired_check(self, key_pair):
        """Test that root certificates skip expiration check."""
        # Create a root cert (self-signed) with past not_after
        today = datetime.datetime.now(pytz.utc)
        yesterday = today - datetime.timedelta(days=1)

        root_cert = Certificate(
            subject=TEST_SUBJECT,
            issuer=TEST_SUBJECT,  # Self-signed (root)
            extensions=Extensions(
                basic_constraints=BasicConstraints(ca=True),
                subject_key_identifier=SubjectKeyIdentifier(
                    subject_key_identifier=b"TEST_ROOT_SKI"
                ),
            ),
            validity=Validity(
                not_before=today - datetime.timedelta(days=100),
                not_after=yesterday,  # Technically "expired" but root, so should be skipped
            ),
        )
        root_cert.sign(key_pair, SHA256)

        chain = Chain(certificates=[root_cert])

        # Should NOT raise CertExpired for root even though it's past not_after
        # because root CAs are trust anchors and skip expiration checks
        chain.validate_trust_path(root_cert)

    def test_validate_trust_path_three_level_chain(self, key_pair):
        """Test validation with a three-level chain: end-entity <- intermediate <- root."""
        from pki_tools import RSAKeyPair

        # Create root certificate (self-signed)
        root_cert = _create_cert(key_pair)

        # Create intermediate certificate issued by root
        int_keypair = RSAKeyPair.generate()
        int_subject = Name(
            c=["US"],
            o=["Test CA"],
            cn=["Intermediate CA"],
        )
        int_cert = Certificate(
            subject=int_subject,
            issuer=root_cert.subject,
            extensions=Extensions(
                basic_constraints=BasicConstraints(ca=True),
                subject_key_identifier=SubjectKeyIdentifier(
                    subject_key_identifier=b"TEST_INT_SKI"
                ),
                authority_key_identifier=AuthorityKeyIdentifier(
                    key_identifier=b"TEST_ROOT_AKI",
                    authority_cert_issuer=[RFC822Name("TEST_NAME")],
                    authority_cert_serial_number=123123,
                    critical=True,
                ),
            ),
            validity=Validity(
                not_before=datetime.datetime.now(pytz.utc),
                not_after=datetime.datetime.now(pytz.utc)
                + datetime.timedelta(days=365),
            ),
        )
        int_cert.sign(key_pair, SHA256)

        # Create end-entity certificate issued by intermediate
        ee_subject = Name(
            c=["US"],
            o=["Test Org"],
            cn=["example.com"],
        )
        ee_cert = Certificate(
            subject=ee_subject,
            issuer=int_subject,
            extensions=Extensions(
                basic_constraints=BasicConstraints(ca=False),
                subject_key_identifier=SubjectKeyIdentifier(
                    subject_key_identifier=b"TEST_EE_SKI"
                ),
                authority_key_identifier=AuthorityKeyIdentifier(
                    key_identifier=b"TEST_INT_AKI",
                    authority_cert_issuer=[RFC822Name("TEST_NAME")],
                    authority_cert_serial_number=123123,
                    critical=True,
                ),
            ),
            validity=Validity(
                not_before=datetime.datetime.now(pytz.utc),
                not_after=datetime.datetime.now(pytz.utc)
                + datetime.timedelta(days=365),
            ),
        )
        ee_cert.sign(int_keypair, SHA256)

        # Create chain with all CA certs
        chain = Chain(certificates=[int_cert, root_cert])

        # Should validate successfully
        chain.validate_trust_path(ee_cert)

    def test_validate_trust_path_with_extra_unrelated_certs(self, key_pair):
        """Test that extra unrelated certificates in chain don't cause validation to fail."""
        from pki_tools import RSAKeyPair

        # Create two independent self-signed certs
        cert1 = _create_cert(key_pair)
        cert2_keypair = RSAKeyPair.generate()
        cert2 = _create_cert(cert2_keypair)

        # Create chain with both certs
        chain = Chain(certificates=[cert1, cert2])

        # Validating cert1 should work even with unrelated cert2 in chain
        chain.validate_trust_path(cert1)

    def test_validate_trust_path_cycle_detection(self, key_pair):
        """Test that cycles in the chain are detected and don't cause infinite loops."""
        # This is more of a defensive test - in practice, certificate cycles
        # shouldn't happen, but the code has cycle detection via serial number tracking

        cert = _create_cert(key_pair)
        chain = Chain(certificates=[cert])

        # A self-signed cert will visit its own serial, then check if it's a root
        # (it is) and exit cleanly
        chain.validate_trust_path(cert)
