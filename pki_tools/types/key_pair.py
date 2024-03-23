import abc
import importlib
import re
from enum import Enum
from typing import Dict, Type, Optional, get_args

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
)
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    rsa,
    ed25519,
    ed448,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)

from pydantic import BaseModel

from pki_tools.types.crypto_parser import (
    CryptoConfig,
    HelperFunc,
    InitCryptoParser,
)
from pki_tools.types.signature_algorithm import PKCS1v15Padding
from pki_tools.types.utils import _byte_to_hex, _hex_to_byte


PUBLIC_KEY_REGEXP = re.compile(
    r"\s*-+BEGIN PUBLIC KEY-+[\w+/\s=]*-+END PUBLIC KEY-+\s*"
)
PRIVATE_KEY_REGEXP = re.compile(
    r"\s*-+BEGIN.+PRIVATE KEY-+[\w+/\s=]*-+END.+PRIVATE KEY-+\s*"
)


class CryptoPrivateKey(InitCryptoParser, abc.ABC):
    """
    Represents a cryptographic private key.
    """

    @classmethod
    def from_cryptography(
        cls: Type["CryptoPrivateKey"],
        key: CertificateIssuerPrivateKeyTypes,
    ) -> "CryptoPrivateKey":
        """
        Create a CryptoPrivateKey from a cryptography private key.

        Args:
            key: The cryptography private key.

        Returns:
            The CryptoPrivateKey object.
        """
        types = get_args(CertificateIssuerPrivateKeyTypes)

        name = None
        for check_type in types:
            if isinstance(key, check_type):
                name = check_type.__name__
                break

        return globals()[name].from_cryptography(key)

    @property
    def der_bytes(self) -> bytes:
        """
        Property to get the DER encoding of the public key.

        Returns:
            bytes: The DER encoded public key.
        """
        return self._crypto_object.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def pem_bytes(self) -> bytes:
        """
        Property to get the PEM encoding of the private key.

        Returns:
            bytes: The PEM encoded private key.
        """
        kwargs = {
            "encoding": serialization.Encoding.PEM,
            "encryption_algorithm": serialization.NoEncryption(),
            "format": serialization.PrivateFormat.TraditionalOpenSSL,
        }

        if "Ed" in self.__class__.__name__:
            kwargs["format"] = serialization.PrivateFormat.PKCS8

        return self._crypto_object.private_bytes(**kwargs)

    @classmethod
    def _crypto_config(cls) -> CryptoConfig:
        return CryptoConfig(
            load_pem=HelperFunc(
                func=serialization.load_pem_private_key,
                kwargs={"password": None},
            ),
            load_der=HelperFunc(
                func=serialization.load_der_private_key,
                kwargs={"password": None},
            ),
            pem_regexp=PRIVATE_KEY_REGEXP,
        )


class CryptoPublicKey(InitCryptoParser, abc.ABC):
    """
    Represents a cryptographic public key.
    """

    @classmethod
    def from_cryptography(
        cls: Type["CryptoPublicKey"],
        key: CertificateIssuerPublicKeyTypes,
    ) -> "CryptoPublicKey":
        """
        Create a CryptoPublicKey from a cryptography public key.

        Args:
            key: The cryptography public key.

        Returns:
            The created CryptoPublicKey.
        """
        types = get_args(CertificateIssuerPublicKeyTypes)

        name = None
        for check_type in types:
            if isinstance(key, check_type):
                name = check_type.__name__
                break

        return globals()[name].from_cryptography(key)

    @property
    def der_bytes(self) -> bytes:
        """
        Property to get the DER encoding of the public key.

        Returns:
            bytes: The DER encoded public key.
        """
        return self._crypto_object.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def ocsp_bytes(self) -> bytes:
        """
        The bytes used for the OCSP Response hash

        Returns:
            bytes: The bytes used for the OCSP Response hash
        """
        return self.der_bytes

    @property
    def pem_bytes(self) -> bytes:
        """
        Property to get the PEM encoding of the public key.

        Returns:
            bytes: The PEM encoded public key.
        """
        return self._crypto_object.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @abc.abstractmethod
    def verify(self, signed: InitCryptoParser) -> None:
        """
        Verifies the signature of a signed object.

        Args:
            signed: the signed object to verify.
        """

    @classmethod
    def _crypto_config(cls) -> CryptoConfig:
        return CryptoConfig(
            load_pem=HelperFunc(func=serialization.load_pem_public_key),
            load_der=HelperFunc(func=serialization.load_der_public_key),
            pem_regexp=PUBLIC_KEY_REGEXP,
        )


class CryptoKeyPair(BaseModel):
    """
    Represents a cryptographic key pair.

    Arguments:
        private_key: The private key
        public_key: The public key
    """

    private_key: CryptoPrivateKey
    public_key: CryptoPublicKey

    _init_func = "create"

    @classmethod
    @abc.abstractmethod
    def generate(cls: Type["CryptoKeyPair"], *args) -> "CryptoKeyPair":
        """
        Abstract method to generate a cryptographic key pair.

        Returns:
            The generated cryptographic key pair.
        """
        raise NotImplementedError

    def __str__(self):
        name = self.__class__.__name__
        d = {name: {}}
        if self.private_key is not None:
            d[name] = self.private_key._string_dict()
        else:
            d[name] = self.public_key._string_dict()
        return yaml.dump(d, indent=2)


class DSAPublicKey(CryptoPublicKey):
    """
    Represents a DSA cryptographic key pair.
    """

    key_size: int

    y: int
    p: int
    q: int
    g: int

    @classmethod
    def from_cryptography(
        cls: Type["DSAPublicKey"],
        key: dsa.DSAPublicKey,
    ) -> "DSAPublicKey":
        """
        Create a DSAKeyPair from a cryptography key.

        Args:
            key: The [cryptography.hazmat.primitives.asymmetric.dsa][]
                public key.

        Returns:
            DSAKeyPair: The DSA key pair.


        """
        public_numbers = key.public_numbers()
        param_numbers = key.parameters().parameter_numbers()

        ret = cls(
            y=public_numbers.y,
            p=param_numbers.p,
            q=param_numbers.q,
            g=param_numbers.g,
            key_size=key.key_size,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    @property
    def ocsp_bytes(self) -> bytes:
        """
        The bytes used for the OCSP Response hash

        Returns:
            bytes: The bytes used for the OCSP Response hash
        """
        return self._crypto_object.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

    def verify(self, signed: InitCryptoParser):
        self._crypto_object.verify(
            signed._crypto_object.signature,
            signed.tbs_bytes,
            signed._crypto_object.signature_hash_algorithm,
        )

    def _to_cryptography(self) -> dsa.DSAPublicKey:
        public_numbers = dsa.DSAPublicNumbers(
            y=self.y,
            parameter_numbers=dsa.DSAParameterNumbers(
                p=self.p, q=self.q, g=self.g
            ),
        )
        return public_numbers.public_key()

    def _string_dict(self) -> Dict[str, str]:
        return {
            "key_size": str(self.key_size),
            "public_key_y": str(self.y),
            "prime_p": str(self.p),
            "subprime_q": str(self.q),
            "generator_g": str(self.g),
        }


class DSAPrivateKey(CryptoPrivateKey):
    """
    Represents a DSA cryptographic private key.
    """

    key_size: int
    x: int

    y: int
    p: int
    q: int
    g: int

    @classmethod
    def from_cryptography(
        cls: Type["DSAPrivateKey"],
        key: dsa.DSAPrivateKey,
    ) -> "DSAPrivateKey":
        """
        Create a DSAPrivateKey from a cryptography key.

        Args:
            key: The [cryptography.hazmat.primitives.asymmetric.dsa][]
                private key.

        Returns:
            DSAKeyPair: The DSA private key.
        """
        x = key.private_numbers().x

        public_numbers = key.public_key().public_numbers()
        param_numbers = key.parameters().parameter_numbers()

        ret = cls(
            x=x,
            y=public_numbers.y,
            p=param_numbers.p,
            q=param_numbers.q,
            g=param_numbers.g,
            key_size=key.key_size,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def _to_cryptography(self) -> dsa.DSAPrivateKey:
        public_numbers = dsa.DSAPublicNumbers(
            y=self.y,
            parameter_numbers=dsa.DSAParameterNumbers(
                p=self.p, q=self.q, g=self.g
            ),
        )

        private_numbers = dsa.DSAPrivateNumbers(
            x=self.x, public_numbers=public_numbers
        )
        return private_numbers.private_key()

    def _string_dict(self) -> Dict[str, str]:
        return {
            "key_size": str(self.key_size),
            "public_key_y": str(self.y),
            "prime_p": str(self.p),
            "subprime_q": str(self.q),
            "generator_g": str(self.g),
        }


class DSAKeyPair(CryptoKeyPair):
    """
    Describes a DSA Key Pair including the public and private DSA keys.

    --8<-- "docs/examples/key_pair_dsa.md"
    """

    @classmethod
    def generate(cls: Type["DSAKeyPair"], key_size: int) -> "DSAKeyPair":
        """
        Generate a DSA cryptographic key pair.

        Args:
            key_size: The size of the key.

        Returns:
            The generated DSA key pair.
        """
        crypto_private = dsa.generate_private_key(key_size=key_size)
        crypto_public = crypto_private.public_key()

        return cls(
            private_key=DSAPrivateKey.from_cryptography(crypto_private),
            public_key=DSAPublicKey.from_cryptography(crypto_public),
        )


class RSAPrivateKey(CryptoPrivateKey):
    """
    Represents an RSA cryptographic key pair.
    """

    key_size: int

    e: int
    n: int

    d: Optional[int]
    p: Optional[int]
    q: Optional[int]
    dmp1: Optional[int]
    dmq1: Optional[int]
    iqmp: Optional[int]

    @classmethod
    def from_cryptography(
        cls: Type["RSAPrivateKey"],
        key: rsa.RSAPrivateKey,
    ) -> "RSAPrivateKey":
        """
        Create an RSA private key from a cryptography key.

        Args:
            key: The cryptography private key.

        Returns:
            An RSAPrivateKey object
        """

        private_numbers = key.private_numbers()
        public_numbers = private_numbers.public_numbers
        d = private_numbers.d
        p = private_numbers.p
        q = private_numbers.q
        dmp1 = private_numbers.dmp1
        dmq1 = private_numbers.dmq1
        iqmp = private_numbers.iqmp

        ret = cls(
            e=public_numbers.e,
            n=public_numbers.n,
            d=d,
            p=p,
            q=q,
            dmp1=dmp1,
            dmq1=dmq1,
            iqmp=iqmp,
            key_size=key.key_size,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def _to_cryptography(self) -> rsa.RSAPrivateKey:
        public_numbers = rsa.RSAPublicNumbers(e=self.e, n=self.n)

        private_numbers = rsa.RSAPrivateNumbers(
            p=self.p,
            q=self.q,
            d=self.d,
            dmp1=self.dmp1,
            dmq1=self.dmq1,
            iqmp=self.iqmp,
            public_numbers=public_numbers,
        )
        return private_numbers.private_key()

    def _string_dict(self) -> Dict[str, str]:
        return {
            "key_size": str(self.key_size),
            "public_exponent_e": str(self.e),
            "modulus_n": str(self.n),
            "private_exponent_d": str(self.d),
            "prime_p": str(self.p),
            "prime_q": str(self.q),
            "dmp1": str(self.dmp1),
            "dmq1": str(self.dmq1),
            "iqmp": str(self.iqmp),
        }


class RSAPublicKey(CryptoPublicKey):
    """
    Represents an RSA cryptographic key pair.
    """

    key_size: int

    e: int
    n: int

    @classmethod
    def from_cryptography(
        cls: Type["RSAPublicKey"],
        key: rsa.RSAPublicKey,
    ) -> "RSAPublicKey":
        """
        Create an RSA public key from a cryptography public key.

        Args:
            key: The public cryptography key.

        Returns:
            The RSA public key
        """
        public_numbers = key.public_numbers()

        ret = cls(
            e=public_numbers.e,
            n=public_numbers.n,
            key_size=key.key_size,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    @property
    def der_bytes(self) -> bytes:
        """
        Property to get the DER encoding of the public key.

        Returns:
            bytes: The DER encoded public key.
        """
        return self._crypto_object.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.PKCS1,
        )

    def verify(self, signed: InitCryptoParser) -> None:
        return self._crypto_object.verify(
            signed._crypto_object.signature,
            signed.tbs_bytes,
            PKCS1v15Padding()._to_cryptography(),
            signed._crypto_object.signature_hash_algorithm,
        )

    def _to_cryptography(self) -> rsa.RSAPublicKey:
        public_numbers = rsa.RSAPublicNumbers(e=self.e, n=self.n)

        return public_numbers.public_key()

    def _string_dict(self) -> Dict[str, str]:
        return {
            "key_size": str(self.key_size),
            "public_exponent_e": str(self.e),
            "modulus_n": str(self.n),
        }


class RSAKeyPair(CryptoKeyPair):
    """
    Describes an RSA Key Pair including the public and private RSA keys.

    --8<-- "docs/examples/key_pair_rsa.md"
    """

    @classmethod
    def generate(
        cls: Type["RSAKeyPair"], key_size: int = 2048, exponent: int = 65537
    ) -> "RSAKeyPair":
        """
        Generate an RSA cryptographic key pair.

        Args:
            key_size: The size of the key. Defaults to `2048`.
            exponent: The public exponent. Defaults to `65537`.

        Returns:
            The generated RSA key pair.
        """
        crypto_private = rsa.generate_private_key(
            public_exponent=exponent,
            key_size=key_size,
        )
        crypto_public = crypto_private.public_key()

        return cls(
            private_key=RSAPrivateKey.from_cryptography(crypto_private),
            public_key=RSAPublicKey.from_cryptography(crypto_public),
        )


EC_MODULE = importlib.import_module(
    "cryptography.hazmat.primitives.asymmetric.ec"
)


class EllipticCurveName(Enum):
    """
    Elliptic Curve Names
    """

    PRIME192V1 = "PRIME192V1"
    PRIME256V1 = "PRIME256V1"
    SECP192R1 = "SECP192R1"
    SECP224R1 = "SECP224R1"
    SECP256R1 = "SECP256R1"
    SECP384R1 = "SECP384R1"
    SECP521R1 = "SECP521R1"
    SECP256K1 = "SECP256K1"
    SECT163K1 = "SECT163K1"
    SECT233K1 = "SECT233K1"
    SECT283K1 = "SECT283K1"
    SECT409K1 = "SECT409K1"
    SECT571K1 = "SECT571K1"
    SECT163R2 = "SECT163R2"
    SECT233R1 = "SECT233R1"
    SECT283R1 = "SECT283R1"
    SECT409R1 = "SECT409R1"
    SECT571R1 = "SECT571R1"
    BRAINPOOLP256R1 = "BrainpoolP256R1"
    BRAINPOOLP384R1 = "BrainpoolP384R1"
    BRAINPOOLP512R1 = "BrainpoolP512R1"


class EllipticCurvePrivateKey(CryptoPrivateKey):
    """
    Represents an elliptic curve cryptographic private key.
    """

    curve_name: EllipticCurveName

    x: int
    y: int
    d: int

    @classmethod
    def from_cryptography(
        cls: Type["EllipticCurvePrivateKey"],
        key: ec.EllipticCurvePrivateKey,
    ) -> "EllipticCurvePrivateKey":
        """
        Create an EllipticCurvePrivateKey from a cryptography private key.

        Args:
            key: The cryptography private key.

        Returns:
            The EllipticCurvePrivateKey created object
        """

        private_numbers = key.private_numbers()
        public_key = key.public_key()
        public_numbers = public_key.public_numbers()
        curve_name = public_key.curve.name.upper()
        d = private_numbers.private_value

        ret = cls(
            x=public_numbers.x,
            y=public_numbers.y,
            curve_name=EllipticCurveName[curve_name],
            d=d,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def _to_cryptography(
        self,
    ) -> ec.EllipticCurvePrivateKey:
        curve = getattr(EC_MODULE, self.curve_name.value)()
        public_numbers = ec.EllipticCurvePublicNumbers(self.x, self.y, curve)

        private_numbers = ec.EllipticCurvePrivateNumbers(
            private_value=self.d, public_numbers=public_numbers
        )

        return private_numbers.private_key()

    def _string_dict(self) -> Dict[str, str]:
        return {
            "curve_name": self.curve_name.name,
            "x_coordinate": str(self.x),
            "y_coordinate": str(self.y),
        }


class EllipticCurvePublicKey(CryptoPublicKey):
    """
    Represents an elliptic curve cryptographic public key.
    """

    curve_name: EllipticCurveName

    x: int
    y: int

    @classmethod
    def from_cryptography(
        cls: Type["EllipticCurvePublicKey"],
        key: ec.EllipticCurvePublicKey,
    ) -> "EllipticCurvePublicKey":
        """
        Create an EllipticCurvePublicKey from a cryptography public key.

        Args:
            key: The cryptography public key.

        Returns:
            The created EllipticCurvePublicKey object
        """
        public_numbers = key.public_numbers()
        curve_name = key.curve.name.upper()

        ret = cls(
            x=public_numbers.x,
            y=public_numbers.y,
            curve_name=EllipticCurveName[curve_name],
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def verify(self, signed: InitCryptoParser):
        self._crypto_object.verify(
            signed._crypto_object.signature,
            signed.tbs_bytes,
            ec.ECDSA(signed._crypto_object.signature_hash_algorithm),
        )

    @property
    def ocsp_bytes(self) -> bytes:
        """
        The bytes used for the OCSP Response hash

        Returns:
            bytes: The bytes used for the OCSP Response hash
        """
        return self._crypto_object.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint,
        )

    def _to_cryptography(
        self,
    ) -> ec.EllipticCurvePublicKey:
        curve = getattr(EC_MODULE, self.curve_name.value)()
        public_numbers = ec.EllipticCurvePublicNumbers(self.x, self.y, curve)
        return public_numbers.public_key()

    def _string_dict(self) -> Dict[str, str]:
        return {
            "curve_name": self.curve_name.name,
            "x_coordinate": str(self.x),
            "y_coordinate": str(self.y),
        }


class EllipticCurveKeyPair(CryptoKeyPair):
    """
    Describes an elliptic curve Key Pair including the public and private keys.

    --8<-- "docs/examples/key_pair_ec.md"
    """

    @classmethod
    def generate(
        cls: Type["EllipticCurveKeyPair"], curve_name: EllipticCurveName
    ) -> "EllipticCurveKeyPair":
        """
        Generate an elliptic curve cryptographic key pair.

        Args:
            curve_name: The name of the curve.

        Returns:
            The generated elliptic curve key pair.
        """
        crypto_private = ec.generate_private_key(
            curve=getattr(EC_MODULE, curve_name.value)()
        )
        crypto_public = crypto_private.public_key()

        return cls(
            private_key=EllipticCurvePrivateKey.from_cryptography(
                crypto_private
            ),
            public_key=EllipticCurvePublicKey.from_cryptography(crypto_public),
        )


class Ed448PrivateKey(CryptoPrivateKey):
    public_bytes: str
    private_bytes: str

    @classmethod
    def from_cryptography(
        cls: Type["Ed448PrivateKey"],
        key: ed448.Ed448PrivateKey,
    ) -> "Ed448PrivateKey":
        """
        Create an Ed25519KeyPair from a cryptography private key.

        Args:
            key: The cryptography private key.

        Returns:
            The created Ed448PrivateKey object.
        """

        public_key = key.public_key()
        private_bytes = _byte_to_hex(key.private_bytes_raw())

        ret = cls(
            public_bytes=_byte_to_hex(public_key.public_bytes_raw()),
            private_bytes=private_bytes,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def _to_cryptography(
        self,
    ) -> ed448.Ed448PrivateKey:
        return ed448.Ed448PrivateKey.from_private_bytes(
            _hex_to_byte(self.private_bytes)
        )

    def _string_dict(self) -> Dict[str, str]:
        return {
            "public_bytes": self.public_bytes,
        }


class Ed448PublicKey(CryptoPublicKey):
    public_bytes: str

    @classmethod
    def from_cryptography(
        cls: Type["Ed448PublicKey"],
        key: ed448.Ed448PublicKey,
    ) -> "Ed448PublicKey":
        """
        Create an Ed448PublicKey from a cryptography public key.

        Args:
            key: The cryptography public key.

        Returns:
            The Ed448PublicKey object.
        """
        ret = cls(
            public_bytes=_byte_to_hex(key.public_bytes_raw()),
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def verify(self, signed: InitCryptoParser):
        self._crypto_object.verify(
            signed._crypto_object.signature,
            signed.tbs_bytes,
        )

    def _to_cryptography(
        self,
    ) -> ed448.Ed448PublicKey:
        return ed448.Ed448PublicKey.from_public_bytes(
            _hex_to_byte(self.public_bytes)
        )

    def _string_dict(self) -> Dict[str, str]:
        return {
            "public_bytes": self.public_bytes,
        }


class Ed448KeyPair(CryptoKeyPair):
    """
    Represents an Ed448 cryptographic key pair.

    --8<-- "docs/examples/key_pair_ed448.md"
    """

    @classmethod
    def generate(cls: Type["Ed448KeyPair"]) -> "Ed448KeyPair":
        """
        Generate an Ed448 cryptographic key pair.

        Returns:
            The generated Ed448 key pair.
        """
        crypto_private = ed448.Ed448PrivateKey.generate()
        crypto_public = crypto_private.public_key()

        return cls(
            private_key=Ed448PrivateKey.from_cryptography(crypto_private),
            public_key=Ed448PublicKey.from_cryptography(crypto_public),
        )


class Ed25519PrivateKey(CryptoPrivateKey):
    private_bytes: str
    public_bytes: str

    @classmethod
    def from_cryptography(
        cls: Type["Ed25519PrivateKey"],
        key: ed25519.Ed25519PrivateKey,
    ) -> "Ed25519PrivateKey":
        """
        Create an Ed25519 private key from a cryptography private key.

        Args:
            key: The cryptography private key.

        Returns:
            The created Ed25519PrivateKey object.
        """

        public_key = key.public_key()
        private_bytes = _byte_to_hex(key.private_bytes_raw())

        ret = cls(
            public_bytes=_byte_to_hex(public_key.public_bytes_raw()),
            private_bytes=private_bytes,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def _to_cryptography(
        self,
    ) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.from_private_bytes(
            _hex_to_byte(self.private_bytes)
        )

    def _string_dict(self) -> Dict[str, str]:
        return {
            "public_bytes": self.public_bytes,
        }


class Ed25519PublicKey(CryptoPublicKey):
    public_bytes: str

    @classmethod
    def from_cryptography(
        cls: Type["Ed25519PublicKey"],
        key: ed25519.Ed25519PublicKey,
    ) -> "Ed25519PublicKey":
        """
        Create an Ed25519PublicKey from a cryptography public key.

        Args:
            key: The cryptography public key.

        Returns:
            The Ed25519PublicKey object.
        """
        ret = cls(
            public_bytes=_byte_to_hex(key.public_bytes_raw()),
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def verify(self, signed: InitCryptoParser):
        self._crypto_object.verify(
            signed._crypto_object.signature,
            signed.tbs_bytes,
        )

    def _to_cryptography(
        self,
    ) -> ed25519.Ed25519PublicKey:
        return ed25519.Ed25519PublicKey.from_public_bytes(
            _hex_to_byte(self.public_bytes)
        )

    def _string_dict(self) -> Dict[str, str]:
        return {
            "public_bytes": self.public_bytes,
        }


class Ed25519KeyPair(CryptoKeyPair):
    """
    Represents an Ed25519 cryptographic key pair.

    --8<-- "docs/examples/key_pair_ed25519.md"
    """

    @classmethod
    def generate(cls: Type["Ed25519KeyPair"]) -> "Ed25519KeyPair":
        """
        Generate an Ed25519KeyPair cryptographic key pair.

        Returns:
            The generated Ed25519 key pair.
        """
        crypto_private = ed25519.Ed25519PrivateKey.generate()
        crypto_public = crypto_private.public_key()

        return cls(
            private_key=Ed25519PrivateKey.from_cryptography(crypto_private),
            public_key=Ed25519PublicKey.from_cryptography(crypto_public),
        )
