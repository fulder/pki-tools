from typing import Type, Optional
import re

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from loguru import logger

from pki_tools.exceptions import CsrLoadError
from pki_tools.types.certificate import _is_pem_csr_string
from pki_tools.types.crypto_parser import CryptoParser
from pki_tools.types.name import Name
from pki_tools.types.extensions import Extensions
from pki_tools.types.signature_algorithm import SignatureAlgorithm
from pki_tools.types.subject_public_key_info import SubjectPublicKeyInfo
from pki_tools.types.utils import _byte_to_hex


class CertificateSigningRequest(CryptoParser):
    subject: Name
    extensions: Optional[Extensions]
    signature_algorithm: Optional[SignatureAlgorithm]
    public_key: SubjectPublicKeyInfo
    attributes: Optional[dict]

    @classmethod
    def from_cryptography(
        cls: Type["CertificateSigningRequest"],
        crypto_csr: x509.CertificateSigningRequest,
    ) -> "CertificateSigningRequest":
        attributes = {}
        for att in crypto_csr.attributes:
            attributes[att.oid.dotted_string] = att.value

        ret = cls(
            subject=Name.from_cryptography(crypto_csr.subject),
            extensions=Extensions.from_cryptography(crypto_csr.extensions),
            signature_algorithm=SignatureAlgorithm(
                algorithm=crypto_csr.signature_hash_algorithm,
                # Add after 42.0.0 release:
                # parameters=crypto_csr.signature_algorithm_parameters
            ),
            signature_value=_byte_to_hex(crypto_csr.signature),
            public_key=SubjectPublicKeyInfo.from_cryptography(
                crypto_csr.public_key()
            ),
            attributes=attributes,
        )
        ret._x509_obj = crypto_csr
        return ret

    @classmethod
    def from_pem_string(cls: Type["CertificateSigningRequest"], csr_pem) -> "CertificateSigningRequest":
        """
        Loads a CSR from a PEM string into a
        [CertificateSigningRequest](https://pki-tools.fulder.dev/pki_tools/types/#certificatesigningrequest)
        object

        Arguments:
            csr_pem -- The PEM encoded CSR in string format
        Returns:
            A
            [CertificateSigningRequest](https://pki-tools.fulder.dev/pki_tools/types/#certificatesigningrequest)
            created from the PEM
        Raises:
             exceptions.CsrLoadError - If the CSR could not be loaded
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
    def from_file(cls: Type["CertificateSigningRequest"], file_path: str) -> "CertificateSigningRequest":
        """
        Reads a file containing one PEM CSR into a
        [CertificateSigningRequest](https://pki-tools.fulder.dev/pki_tools/types/#certificatesigningrequest)
        object

        Arguments:
            file_path -- Path and filename of the PEM CSR
        Returns:
             The
             [CertificateSigningRequest](https://pki-tools.fulder.dev/pki_tools/types/#certificatesigningrequest)
             representing the CSR loaded from file
        """

        with open(file_path, "r") as f:
            csr_pem = f.read()

        return CertificateSigningRequest.from_pem_string(csr_pem)

    @property
    def tbs_bytes(self) -> bytes:
        return self._x509_obj.tbs_certrequest_bytes

    @property
    def pem_string(self):
        return self._x509_obj.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()

    def to_file(self, file_path):
        with open(file_path, "w") as f:
            f.write(self.pem_string)

    def _string_dict(self):
        ret = {
            "Certificate Signing Request":
                {
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

    def __str__(self) -> str:
        return yaml.safe_dump(
            self._string_dict(),
            indent=2,
            default_flow_style=False,
            explicit_start=True,
            default_style="",
        )
