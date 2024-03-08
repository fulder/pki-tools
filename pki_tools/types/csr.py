from typing import Type, Optional, Dict
import re

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from loguru import logger

from pki_tools.exceptions import CsrLoadError, MissingInit
from pki_tools.types.key_pair import KeyPair, CryptoKeyPair
from pki_tools.types.certificate import _is_pem_csr_string
from pki_tools.types.crypto_parser import InitCryptoParser
from pki_tools.types.name import Name
from pki_tools.types.extensions import Extensions
from pki_tools.types.signature_algorithm import (
    SignatureAlgorithm,
)
from pki_tools.types.utils import _byte_to_hex


class CertificateSigningRequest(InitCryptoParser):
    """
    Represents a certificate signing request (CSR).

    Attributes:
        subject: The subject of the CSR.
        public_key: Public key associated with the CSR.
        extensions: Extensions associated with the CSR.
        attributes: Attributes of the CSR.
        signature_algorithm: Signature algorithm used while signing the CSR.
    """

    subject: Name

    public_key: Optional[KeyPair] = None
    extensions: Optional[Extensions] = None
    attributes: Optional[Dict[str, bytes]] = None
    signature_algorithm: Optional[SignatureAlgorithm] = None

    _private_key: Optional[CryptoKeyPair]

    @classmethod
    def from_cryptography(
        cls: Type["CertificateSigningRequest"],
        crypto_csr: x509.CertificateSigningRequest,
    ) -> "CertificateSigningRequest":
        """
        Create a CertificateSigningRequest object from a cryptography
        CertificateSigningRequest.

        Args:
            crypto_csr: Cryptography CertificateSigningRequest.

        Returns:
            Instance of CertificateSigningRequest.
        """
        attributes = {}
        for att in crypto_csr.attributes:
            attributes[att.oid.dotted_string] = att.value

        ret = cls(
            subject=Name.from_cryptography(crypto_csr.subject),
            extensions=Extensions.from_cryptography(crypto_csr.extensions),
            signature_algorithm=SignatureAlgorithm.from_cryptography(
                crypto_csr.signature_hash_algorithm,
                crypto_csr.signature_algorithm_parameters,
            ),
            signature_value=_byte_to_hex(crypto_csr.signature),
            public_key=KeyPair.from_cryptography(crypto_csr.public_key()),
            attributes=attributes,
            _x509_obj=crypto_csr,
        )
        ret._x509_obj = crypto_csr
        return ret

    @classmethod
    def from_pem_string(
        cls: Type["CertificateSigningRequest"], csr_pem: str
    ) -> "CertificateSigningRequest":
        """
        Load a CSR from a PEM string into a CertificateSigningRequest object.

        Args:
            csr_pem: PEM encoded CSR in string format.

        Returns:
            Instance of CertificateSigningRequest.

        Raises:
            CsrLoadError: If the CSR could not be loaded.
        """
        try:
            csr_pem = re.sub(r"\n\s*", "\n", csr_pem)
            if not _is_pem_csr_string(csr_pem):
                raise ValueError

            csr_cert = x509.load_pem_x509_csr(csr_pem.encode())
            return CertificateSigningRequest.from_cryptography(csr_cert)
        except ValueError as e:
            logger.bind(csr=csr_pem).debug("Failed to load CSR from PEM")
            raise CsrLoadError(e)

    @classmethod
    def from_file(
        cls: Type["CertificateSigningRequest"], file_path: str
    ) -> "CertificateSigningRequest":
        """
        Read a file containing a PEM CSR into a CertificateSigningRequest
        object.

        Args:
            file_path: Path and filename of the PEM CSR.

        Returns:
            Instance of CertificateSigningRequest representing the CSR loaded
            from file.
        """
        with open(file_path, "r") as f:
            csr_pem = f.read()

        return CertificateSigningRequest.from_pem_string(csr_pem)

    @property
    def tbs_bytes(self) -> bytes:
        """
        Get the bytes to be signed of the CSR.

        Returns:
            TBS bytes of the CSR.
        """
        return self._crypto_object.tbs_certrequest_bytes

    @property
    def pem_bytes(self) -> bytes:
        """
        Get the PEM bytes of the CSR.

        Returns:
            PEM bytes of the CSR.
        """
        return self._crypto_object.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    @property
    def pem_string(self) -> str:
        """
        Get the PEM string representation of the CSR.

        Returns:
            PEM string of the CSR.
        """
        return self.pem_bytes.decode()

    def to_file(self, file_path: str) -> None:
        """
        Save the CSR to a file.

        Args:
            file_path: Path to save the file.
        """
        with open(file_path, "w") as f:
            f.write(self.pem_string)

    def sign(
        self, key_pair: CryptoKeyPair, signature_algorithm: SignatureAlgorithm
    ):
        """
        Sign the CSR with the provided key pair and signature algorithm.

        Args:
            key_pair: Key pair with the private key to use while signing the
                CSR
            signature_algorithm: Signature algorithm to use for signing.
        """
        self._private_key = key_pair
        self.signature_algorithm = signature_algorithm
        self._x509_obj = self._to_cryptography()

    def _string_dict(self):
        ret = {
            "Certificate Signing Request": {
                "Subject": self.subject._string_dict(),
                "Extensions": self.extensions._string_dict(),
                "Signature Algorithm": self.signature_algorithm._string_dict(),
                "Public Key": self.public_key._string_dict(),
            }
        }
        if self.attributes is not None:
            attributes = []

            for k in self.attributes:
                val = self.attributes[k]
                if k == "1.2.840.113549.1.9.14":
                    val = _byte_to_hex(val)
                elif k == "1.2.840.113549.1.9.7":
                    val = val.decode()
                attributes.append(f"{k}: {str(val)}")

            ret["Certificate Signing Request"]["Attributes"] = attributes
        return ret

    def _to_cryptography(self) -> x509.CertificateSigningRequest:
        if not hasattr(self, "_private_key"):
            raise MissingInit(
                f"Please use CertificateSigningRequest."
                f"{self._init_func} function"
            )

        crypto_key = self._private_key._to_cryptography()
        if not hasattr(crypto_key, "public_key"):
            raise MissingInit("Use private key not public")

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(self.subject._to_cryptography())

        if self.extensions is not None:
            for extension in self.extensions:
                builder = builder.add_extension(
                    extension._to_cryptography(), extension.critical
                )

        if self.attributes is not None:
            for attribute_oid, value in self.attributes.items():
                oid = x509.ObjectIdentifier(attribute_oid)
                builder = builder.add_attribute(oid, value)

        return builder.sign(
            crypto_key,
            self.signature_algorithm.algorithm._to_cryptography(),
        )

    def __str__(self) -> str:
        return yaml.safe_dump(
            self._string_dict(),
            indent=2,
            default_flow_style=False,
            explicit_start=True,
            default_style="",
        )
