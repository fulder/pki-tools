from typing import Type, Optional, Dict
import re

import yaml
from cryptography import x509

from pki_tools.exceptions import MissingInit
from pki_tools.types.key_pair import (
    CryptoPublicKey,
    CryptoPrivateKey,
    CryptoKeyPair,
    Ed25519PrivateKey,
    Ed448PrivateKey,
)
from pki_tools.types.crypto_parser import (
    InitCryptoParser,
    CryptoConfig,
    HelperFunc,
)
from pki_tools.types.name import Name
from pki_tools.types.extensions import Extensions
from pki_tools.types.signature_algorithm import (
    SignatureAlgorithm,
)
from pki_tools.types.utils import _byte_to_hex

PEM_CSR_REGEX = re.compile(
    r"\s*-+BEGIN CERTIFICATE REQUEST-+[\w+/\s=]*-+END CERTIFICATE REQUEST-+\s*"
)


class CertificateSigningRequest(InitCryptoParser):
    """
    Represents a certificate signing request (CSR).

    Attributes:
        subject: The subject of the CSR.
        public_key: Public key associated with the CSR.
        extensions: Extensions associated with the CSR.
        attributes: Attributes of the CSR.
        signature_algorithm: Signature algorithm used while signing the CSR.

    --8<-- "docs/examples/csr.md"
    """

    subject: Name

    public_key: Optional[CryptoPublicKey] = None
    extensions: Optional[Extensions] = None
    attributes: Optional[Dict[str, bytes]] = None
    signature_algorithm: Optional[SignatureAlgorithm] = None

    _private_key: Optional[CryptoPrivateKey]

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

        --8<-- "docs/examples/csr_from_cryptography.md"
        """
        attributes = {}
        for att in crypto_csr.attributes:
            attributes[att.oid.dotted_string] = att.value

        signature_algorithm = None
        if crypto_csr.signature_hash_algorithm:
            signature_algorithm = SignatureAlgorithm.from_cryptography(
                crypto_csr.signature_hash_algorithm,
                crypto_csr.signature_algorithm_parameters,
            )

        ret = cls(
            subject=Name.from_cryptography(crypto_csr.subject),
            extensions=Extensions.from_cryptography(crypto_csr.extensions),
            signature_algorithm=signature_algorithm,
            signature_value=_byte_to_hex(crypto_csr.signature),
            public_key=CryptoPublicKey.from_cryptography(
                crypto_csr.public_key()
            ),
            attributes=attributes,
            _x509_obj=crypto_csr,
        )
        ret._x509_obj = crypto_csr
        return ret

    @property
    def tbs_bytes(self) -> bytes:
        """
        Get the bytes to be signed of the CSR.

        Returns:
            TBS bytes of the CSR.
        """
        return self._crypto_object.tbs_certrequest_bytes

    def sign(
        self,
        key_pair: CryptoKeyPair,
        signature_algorithm: Optional[SignatureAlgorithm] = None,
    ):
        """
        Sign the CSR with the provided key pair and signature algorithm.

        Args:
            key_pair: Key pair with the private key to use while signing the
                CSR
            signature_algorithm: Signature algorithm to use for signing.
        """
        self._private_key = key_pair.private_key
        self.signature_algorithm = signature_algorithm
        self._x509_obj = self._to_cryptography()

    def _string_dict(self):
        ret = {
            "Certificate Signing Request": {
                "Subject": str(self.subject),
                "Public Key": self.public_key._string_dict(),
            }
        }
        if self.extensions:
            ret["Extensions"] = self.extensions._string_dict()
        if self.signature_algorithm is not None:
            signature_alg = self.signature_algorithm.algorithm.name.value
            ret["Signature Algorithm"] = signature_alg
        if self.attributes is not None:
            attributes = []

            for k in self.attributes:
                val = self.attributes[k]
                if k == "1.2.840.113549.1.9.14":
                    val = _byte_to_hex(val)
                elif k == "1.2.840.113549.1.9.7":
                    val = val.decode()
                attributes.append(f"{k}: {str(val)}")

            if attributes:
                ret["Certificate Signing Request"]["Attributes"] = attributes
        return ret

    def _to_cryptography(self) -> x509.CertificateSigningRequest:
        if not hasattr(self, "_private_key"):
            raise MissingInit(
                f"Please use CertificateSigningRequest."
                f"{self._init_func} function"
            )

        crypto_key = self._private_key._to_cryptography()

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

        if isinstance(self._private_key, Ed448PrivateKey) or isinstance(
            self._private_key, Ed25519PrivateKey
        ):
            alg = None
        else:
            alg = self.signature_algorithm.algorithm._to_cryptography()

        return builder.sign(crypto_key, alg)

    def __str__(self) -> str:
        return yaml.safe_dump(
            self._string_dict(),
            indent=2,
            default_flow_style=False,
            explicit_start=True,
            default_style="",
        )

    @classmethod
    def _crypto_config(cls) -> CryptoConfig:
        return CryptoConfig(
            load_pem=HelperFunc(func=x509.load_pem_x509_csr),
            load_der=HelperFunc(func=x509.load_der_x509_csr),
            pem_regexp=PEM_CSR_REGEX,
        )
