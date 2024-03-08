import abc
import importlib
from typing import Dict, Type, Union, Optional, get_args

from cryptography.hazmat.primitives import serialization
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

from pydantic import ConfigDict

from pki_tools.exceptions import InvalidKeyType
from pki_tools.types.crypto_parser import (
    CryptoObject,
    InitCryptoParser,
)
from pki_tools.types.utils import _byte_to_hex, _hex_to_byte, _der_key


class CryptoKeyPair(InitCryptoParser):
    """
    Represents a cryptographic key pair.
    """

    _init_func = "generate"

    @classmethod
    @abc.abstractmethod
    def generate(cls: Type["CryptoKeyPair"], *args) -> "CryptoKeyPair":
        """
        Abstract method to generate a cryptographic key pair.

        Returns:
            The generated cryptographic key pair.
        """
        raise NotImplementedError

    @property
    def der_public_key(self) -> bytes:
        """
        Property to get the DER encoding of the public key.

        Returns:
            bytes: The DER encoded public key.
        """
        return _der_key(self._crypto_object.public_key())

    @property
    def pem_public_key(self) -> bytes:
        """
        Property to get the PEM encoding of the public key.

        Returns:
            bytes: The PEM encoded public key.
        """
        public_key = self._crypto_object
        if hasattr(self._crypto_object, "public_key"):
            public_key = public_key.public_key()

        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def pem_private_key(self) -> bytes:
        """
        Property to get the PEM encoding of the private key.

        Returns:
            bytes: The PEM encoded private key.
        """
        if not hasattr(self._crypto_object, "public_key"):
            raise InvalidKeyType("Can't get private key using public key")

        kwargs = {
            "encoding": serialization.Encoding.PEM,
            "encryption_algorithm": serialization.NoEncryption(),
            "format": serialization.PrivateFormat.TraditionalOpenSSL,
        }

        if "Ed" in self.__class__.__name__:
            kwargs["format"] = serialization.PrivateFormat.PKCS8

        return self._crypto_object.private_bytes(**kwargs)

    def private_key_to_file(self, file_path: str) -> None:
        """
        Method to write the PEM-encoded private key to a file.

        Args:
            file_path (str): Path to the output file.
        """
        with open(file_path, "w") as f:
            f.write(self.pem_private_key.decode())

    def public_key_to_file(self, file_path: str):
        """
        Method to write the PEM-encoded public key to a file.

        Args:
            file_path (str): Path to the output file.
        """
        with open(file_path, "w") as f:
            f.write(self.pem_public_key.decode())


class DSAKeyPair(CryptoKeyPair):
    """
    Represents a DSA cryptographic key pair.
    """

    key_size: int

    y: int
    p: int
    q: int
    g: int

    x: Optional[int]

    @classmethod
    def generate(cls: Type["DSAKeyPair"], key_size: int) -> "DSAKeyPair":
        """
        Generate a DSA cryptographic key pair.

        Args:
            key_size: The size of the key.

        Returns:
            The generated DSA key pair.
        """
        new_key = dsa.generate_private_key(key_size=key_size)
        return DSAKeyPair.from_cryptography(new_key)

    @classmethod
    def from_cryptography(
        cls: Type["DSAKeyPair"],
        key: Union[dsa.DSAPrivateKey, dsa.DSAPublicKey],
    ) -> "DSAKeyPair":
        """
        Create a DSAKeyPair from a cryptography key.

        Args:
            key: The [cryptography.hazmat.primitives.asymmetric.dsa][]
                public or private key.

        Returns:
            DSAKeyPair: The DSA key pair.
        """
        if isinstance(key, dsa.DSAPrivateKey):
            public_key = key.public_key()
            x = key.private_numbers().x
        elif isinstance(key, dsa.DSAPublicKey):
            public_key = key
            x = None
        else:
            raise TypeError(f"Invalid key type: {type(key)}")

        public_numbers = public_key.public_numbers()
        param_numbers = public_key.parameters().parameter_numbers()

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

    def _to_cryptography(self) -> Union[dsa.DSAPrivateKey, dsa.DSAPublicKey]:
        public_numbers = dsa.DSAPublicNumbers(
            y=self.y,
            parameter_numbers=dsa.DSAParameterNumbers(
                p=self.p, q=self.q, g=self.g
            ),
        )
        if self.x is None:
            return public_numbers.public_key()

        private_numbers = dsa.DSAPrivateNumbers(
            x=self.x, public_numbers=public_numbers
        )
        return private_numbers.private_key()

    def _string_dict(self) -> Dict[str, str]:
        return {
            "key_size": str(self.key_size),
            "public_key_y": self.y,
            "prime_p": self.p,
            "subprime_q": self.q,
            "generator_g": self.g,
        }


class RSAKeyPair(CryptoKeyPair):
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
        new_key = rsa.generate_private_key(
            public_exponent=exponent,
            key_size=key_size,
        )
        return RSAKeyPair.from_cryptography(new_key)

    @classmethod
    def from_cryptography(
        cls: Type["RSAKeyPair"],
        key: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey],
    ) -> "RSAKeyPair":
        """
        Create an RSAKeyPair from a cryptography key.

        Args:
            key: The cryptography key.

        Returns:
            The RSA key pair.
        """
        if isinstance(key, rsa.RSAPrivateKey):
            private_numbers = key.private_numbers()
            public_numbers = private_numbers.public_numbers
            d = private_numbers.d
            p = private_numbers.p
            q = private_numbers.q
            dmp1 = private_numbers.dmp1
            dmq1 = private_numbers.dmq1
            iqmp = private_numbers.iqmp
        elif isinstance(key, rsa.RSAPublicKey):
            public_numbers = key.public_numbers()
            d = None
            p = None
            q = None
            dmp1 = None
            dmq1 = None
            iqmp = None
        else:
            raise TypeError(f"Invalid key type: {type(key)}")

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

    def _to_cryptography(self) -> Union[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        public_numbers = rsa.RSAPublicNumbers(e=self.e, n=self.n)

        if self.p is None:
            return public_numbers.public_key()

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


EC_MODULE = importlib.import_module(
    "cryptography.hazmat.primitives.asymmetric.ec"
)


class EllipticCurveKeyPair(CryptoKeyPair):
    """
    Represents an elliptic curve cryptographic key pair.
    """

    curve_name: str

    x: int
    y: int

    d: Optional[int]

    @classmethod
    def generate(
        cls: Type["EllipticCurveKeyPair"], curve_name: str
    ) -> "EllipticCurveKeyPair":
        """
        Generate an elliptic curve cryptographic key pair.

        Args:
            curve_name: The name of the curve.

        Returns:
            The generated elliptic curve key pair.
        """
        allowed = [val.name.upper() for val in ec._CURVE_TYPES.values()]
        if curve_name.upper() not in allowed:
            raise TypeError(
                f"Curve Name: {curve_name} "
                f"doesn't match supported names: {allowed}"
            )

        new_key = ec.generate_private_key(
            curve=getattr(EC_MODULE, curve_name.upper())()
        )

        return EllipticCurveKeyPair.from_cryptography(new_key)

    @classmethod
    def from_cryptography(
        cls: Type["EllipticCurveKeyPair"],
        key: Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> "EllipticCurveKeyPair":
        """
        Create an EllipticCurveKeyPair from a cryptography key.

        Args:
            key: The cryptography key.

        Returns:
            The elliptic curve key pair.
        """
        if isinstance(key, ec.EllipticCurvePrivateKey):
            private_numbers = key.private_numbers()
            public_key = key.public_key()
            public_numbers = public_key.public_numbers()
            curve_name = public_key.curve.name.upper()
            d = private_numbers.private_value
        elif isinstance(key, ec.EllipticCurvePublicKey):
            public_numbers = key.public_numbers()
            curve_name = key.curve.name.upper()
            d = None
        else:
            raise TypeError(f"Invalid key type: {type(key)}")

        ret = cls(
            x=public_numbers.x,
            y=public_numbers.y,
            curve_name=curve_name,
            d=d,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def _to_cryptography(
        self,
    ) -> Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        curve = getattr(EC_MODULE, self.curve_name)()
        public_numbers = ec.EllipticCurvePublicNumbers(self.x, self.y, curve)
        if self.d is None:
            return public_numbers.public_key()

        private_numbers = ec.EllipticCurvePrivateNumbers(
            private_value=self.d, public_numbers=public_numbers
        )

        return private_numbers.private_key()

    def _string_dict(self) -> Dict[str, str]:
        return {
            "curve_name": self.curve_name,
            "x_coordinate": str(self.x),
            "y_coordinate": str(self.y),
            "private_key_d": str(self.d),
        }


class Ed25519KeyPair(CryptoKeyPair):
    """
    Represents an Ed25519 cryptographic key pair.
    """

    public_bytes: str
    private_bytes: Optional[str]

    @classmethod
    def generate(cls: Type["Ed25519KeyPair"]) -> "Ed25519KeyPair":
        """
        Generate an Ed25519 cryptographic key pair.

        Returns:
            The generated Ed25519 key pair.
        """
        new_key = ed25519.Ed25519PrivateKey.generate()
        return Ed25519KeyPair.from_cryptography(new_key)

    @classmethod
    def from_cryptography(
        cls: Type["Ed25519KeyPair"],
        key: Union[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey],
    ) -> "Ed25519KeyPair":
        """
        Create an Ed25519KeyPair from a cryptography key.

        Args:
            key: The cryptography key.

        Returns:
            The Ed25519 key pair.
        """
        private_bytes = None

        if isinstance(key, ed25519.Ed25519PrivateKey):
            public_key = key.public_key()
            private_bytes = _byte_to_hex(key.private_bytes_raw())
        elif isinstance(key, ed25519.Ed25519PublicKey):
            public_key = key
        else:
            raise TypeError(f"Invalid key type: {type(key)}")

        ret = cls(
            public_bytes=_byte_to_hex(public_key.public_bytes_raw()),
            private_bytes=private_bytes,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def _to_cryptography(
        self,
    ) -> Union[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        if self.private_bytes is not None:
            return ed25519.Ed25519PrivateKey.from_private_bytes(
                _hex_to_byte(self.private_bytes)
            )
        else:
            return ed25519.Ed25519PublicKey.from_public_bytes(
                _hex_to_byte(self.public_bytes)
            )

    def _string_dict(self) -> Dict[str, str]:
        return {
            "public_bytes": self.public_bytes,
        }


class Ed448KeyPair(CryptoKeyPair):
    """
    Represents an Ed448 cryptographic key pair.
    """

    public_bytes: str
    private_bytes: Optional[str]

    @classmethod
    def generate(cls: Type["Ed448KeyPair"]) -> "Ed448KeyPair":
        """
        Generate an Ed448 cryptographic key pair.

        Returns:
            The generated Ed448 key pair.
        """
        new_key = ed448.Ed448PrivateKey.generate()
        return Ed448KeyPair.from_cryptography(new_key)

    @classmethod
    def from_cryptography(
        cls: Type["Ed448KeyPair"],
        key: Union[ed448.Ed448PrivateKey, ed448.Ed448PublicKey],
    ) -> "Ed448KeyPair":
        """
        Create an Ed448KeyPair from a cryptography key.

        Args:
            key: The cryptography key.

        Returns:
            The Ed448 key pair.
        """
        private_bytes = None

        if isinstance(key, ed448.Ed448PrivateKey):
            public_key = key.public_key()
            private_bytes = _byte_to_hex(key.private_bytes_raw())
        elif isinstance(key, ed448.Ed448PublicKey):
            public_key = key
        else:
            raise TypeError(f"Invalid key type: {type(key)}")

        ret = cls(
            public_bytes=_byte_to_hex(public_key.public_bytes_raw()),
            private_bytes=private_bytes,
            _x509_obj=key,
        )
        ret._x509_obj = key
        return ret

    def _to_cryptography(
        self,
    ) -> Union[ed448.Ed448PrivateKey, ed448.Ed448PublicKey]:
        if self.private_bytes is not None:
            return ed448.Ed448PrivateKey.from_private_bytes(
                _hex_to_byte(self.private_bytes)
            )
        else:
            return ed448.Ed448PublicKey.from_public_bytes(
                _hex_to_byte(self.public_bytes)
            )

    def _string_dict(self) -> Dict[str, str]:
        return {
            "public_bytes": self.public_bytes,
        }


class KeyPair(InitCryptoParser):
    """
    Represents a cryptographic key pair.

    Attributes:
        algorithm: The key algorithm in string format
        parameters: The dict representation of the key
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    algorithm: str
    parameters: Dict[str, str]

    _init_func = "create"
    _key_pair: CryptoKeyPair

    @classmethod
    def from_cryptography(
        cls: Type["KeyPair"],
        key: Union[
            CertificateIssuerPrivateKeyTypes, CertificateIssuerPublicKeyTypes
        ],
    ) -> "KeyPair":
        """
        Create a KeyPair from a cryptography key.

        Args:
            key: The cryptography key.

        Returns:
            The key pair.
        """
        types = get_args(
            Union[
                CertificateIssuerPrivateKeyTypes,
                CertificateIssuerPublicKeyTypes,
            ]
        )

        name = None
        for check_type in types:
            if isinstance(key, check_type):
                name = check_type.__name__
                break

        class_name = name.replace("PrivateKey", "KeyPair")
        class_name = class_name.replace("PublicKey", "KeyPair")

        key_pair = globals()[class_name].from_cryptography(key)

        ret = cls(
            algorithm=name.replace("Private", ""),
            parameters=key_pair._string_dict(),
            _x509_obj=key_pair._x509_obj,
        )
        ret._x509_obj = key_pair._x509_obj
        ret._key_pair = key_pair
        return ret

    def create(self, key_pair: CryptoKeyPair):
        """
        Create a KeyPair.

        Args:
            key_pair: The cryptographic key pair.
        """
        self._key_pair = key_pair
        self._x509_obj = self._key_pair._to_cryptography()

    def _string_dict(self) -> Dict:
        params = {}
        for k, v in self.parameters.items():
            key = " ".join(ele.title() for ele in k.split("_"))
            if v == "None":
                continue

            params[key] = v

        return {"Public Key Algorithm": self.algorithm, "Parameters": params}

    def _to_cryptography(self) -> CryptoObject:
        return self._crypto_object
