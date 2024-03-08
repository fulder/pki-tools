import importlib
from abc import ABC
from enum import Enum
from typing import Type, Optional, Union, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pydantic import BaseModel, ConfigDict

from pki_tools.exceptions import MissingBlockSize
from pki_tools.types.crypto_parser import CryptoParser

HASHES_MODULE = importlib.import_module(
    "cryptography.hazmat.primitives.hashes"
)


class HashAlgorithmName(Enum):
    """
    Enumeration of hash algorithm names.
    """

    SHA1 = "SHA1"
    SHA512_224 = "SHA512_224"
    SHA512_256 = "SHA512_256"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"
    SHA3_224 = "SHA3_224"
    SHA3_256 = "SHA3_256"
    SHA3_384 = "SHA3_384"
    SHA3_512 = "SHA3_512"
    SHAKE128 = "SHAKE128"
    SHAKE256 = "SHAKE256"
    MD5 = "MD5"
    BLAKE2b = "BLAKE2b"
    BLAKE2s = "BLAKE2s"
    SM3 = "SM3"


class HashAlgorithm(CryptoParser):
    """
    Represents a hash algorithm.

    Attributes:
        name: The name of the hash algorithm.
        block_size: The block size of the hash algorithm.
    """

    name: HashAlgorithmName
    block_size: Optional[int] = None

    @classmethod
    def from_cryptography(
        cls: Type["HashAlgorithm"], x509_obj: hashes.HashAlgorithm
    ) -> "HashAlgorithm":
        """
        Constructs a HashAlgorithm object from a cryptography HashAlgorithm
        object.

        Args:
            x509_obj: The cryptography HashAlgorithm object.

        Returns:
            The constructed HashAlgorithm object.
        """
        return cls(
            name=x509_obj.__class__.__name__,
            block_size=x509_obj.block_size,
            _x509_obj=x509_obj,
        )

    @property
    def der_bytes(self):
        return self._to_cryptography().public_bytes(Encoding.DER)

    def _to_cryptography(self) -> hashes.HashAlgorithm:
        if "SHAKE" in self.name.value:
            if self.block_size is None:
                raise MissingBlockSize("Please set block_size")

            return getattr(HASHES_MODULE, self.name.value)(self.block_size)

        if self.name.value == "BLAKE2s":
            return getattr(HASHES_MODULE, self.name.value)(32)
        elif self.name.value == "BLAKE2b":
            return getattr(HASHES_MODULE, self.name.value)(64)

        return getattr(HASHES_MODULE, self.name.value)()

    def _string_dict(self) -> Dict[str, str]:
        return {"algorithm": self.name.value}


class Padding(CryptoParser, ABC):
    """
    Abstract base class representing padding.
    """


class PSSPaddingLenght(Enum):
    """
    Enumeration of PSS padding lengths.
    """

    _MaxLength = "_MaxLength"
    _Auto = "_Auto"
    _DigestLength = "_DigestLength"


class PSSPadding(Padding):
    """
    Represents PSS padding.

    Attributes:
        mgf: The mask generation function.
        length: The length of the padding.
    """

    mgf: HashAlgorithm
    length: Union[int, PSSPaddingLenght]

    @classmethod
    def from_cryptography(
        cls: Type["PSSPadding"], crypto_obj: padding.PSS
    ) -> "PSSPadding":
        """
        Constructs a PSSPadding object from a cryptography PSS object.

        Args:
            crypto_obj: The cryptography PSS object.

        Returns:
            The constructed PSSPadding object.
        """
        salt_length = crypto_obj._salt_length
        if not isinstance(salt_length, int):
            salt_length = PSSPaddingLenght[salt_length.__class__.__name__]

        return cls(
            mgf=crypto_obj._mgf._algorithm,
            length=salt_length,
            _x509_obj=crypto_obj,
        )

    def _to_cryptography(self) -> padding.PSS:
        return padding.PSS(
            mgf=padding.MGF1(self.mgf._to_cryptography()),
            salt_length=getattr(padding, self.length.value),
        )

    def _string_dict(self) -> Dict:
        length = self.length
        if not isinstance(length, int):
            length = self.length.name

        return {
            "mgf": self.mgf._string_dict(),
            "salt_length": length,
        }


class PKCS1v15Padding(Padding):
    """
    Represents PKCS1v15 padding.
    """

    _name: str

    @classmethod
    def from_cryptography(
        cls: Type["PKCS1v15Padding"], crypto_obj: padding.PKCS1v15
    ) -> "PKCS1v15Padding":
        """
        Constructs a PKCS1v15Padding object from a cryptography PKCS1v15
        object.

        Args:
            crypto_obj: The cryptography PKCS1v15 object.

        Returns:
            The constructed PKCS1v15Padding object.
        """
        return cls(_name=crypto_obj.name, _x509_obj=crypto_obj)

    def _to_cryptography(self) -> padding.PKCS1v15:
        return padding.PKCS1v15()

    def _string_dict(self) -> Dict[str, str]:
        return {"name": self._name}


class ECDSAPadding(Padding):
    """
    Represents ECDSA padding.

    Attributes:
        algorithm: The hash algorithm.
        prehashed: Indicates if the data is prehashed.
    """

    algorithm: HashAlgorithm
    prehashed: bool

    @classmethod
    def from_cryptography(
        cls: Type["ECDSAPadding"], crypto_obj: ec.ECDSA
    ) -> "ECDSAPadding":
        """
        Constructs an ECDSAPadding object from a cryptography ECDSA object.

        Args:
            crypto_obj: The cryptography ECDSA object.

        Returns:
            The constructed ECDSAPadding object.
        """
        if isinstance(crypto_obj.algorithm, Prehashed):
            prehashed = True
            algorithm = crypto_obj.algorithm._algorithm
        else:
            prehashed = False
            algorithm = crypto_obj.algorithm

        algorithm = HashAlgorithm.from_cryptography(algorithm)

        return cls(
            algorithm=algorithm,
            prehashed=prehashed,
            _x509_obj=crypto_obj,
        )

    def _to_cryptography(self) -> ec.ECDSA:
        alg = self.algorithm._to_cryptography()
        if self.prehashed:
            alg = Prehashed(alg)

        return ec.ECDSA(algorithm=alg)

    def _string_dict(self) -> Dict:
        length = self.length
        if not isinstance(length, int):
            length = self.length.name

        ret = self.algorithm._string_dict()
        ret["prehashed"] = str(self.prehashed)
        return ret


class SignatureAlgorithm(BaseModel):
    """
    Represents a signature algorithm.

    Attributes:
        algorithm: The hash algorithm.
        parameters: The parameters of the signature algorithm.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    algorithm: HashAlgorithm
    parameters: Optional[
        Union[PSSPadding, PKCS1v15Padding, ECDSAPadding]
    ] = None

    @classmethod
    def from_cryptography(
        cls: Type["SignatureAlgorithm"],
        algorithm: hashes.HashAlgorithm,
        parameters: Union[padding.PSS, padding.PKCS1v15, ec.ECDSA] = None,
    ) -> "SignatureAlgorithm":
        """
        Constructs a SignatureAlgorithm object from cryptography objects.

        Args:
            algorithm: The hash algorithm.
            parameters: The parameters.

        Returns:
            The constructed SignatureAlgorithm object.
        """
        algorithm = HashAlgorithm.from_cryptography(algorithm)

        if parameters is None:
            return cls(algorithm=algorithm)

        if isinstance(parameters, padding.PSS):
            parameters = PSSPadding.from_cryptography(parameters)
        elif isinstance(parameters, padding.PKCS1v15):
            parameters = PKCS1v15Padding.from_cryptography(parameters)
        elif isinstance(parameters, ec.ECDSA):
            parameters = ECDSAPadding.from_cryptography(parameters)

        return cls(algorithm=algorithm, parameters=parameters)

    def _string_dict(self):
        ret = self.algorithm._string_dict()

        if self.parameters is not None:
            ret["parameters"] = self.parameters._string_dict()

        return ret


SHA1 = SignatureAlgorithm(algorithm=HashAlgorithm(name=HashAlgorithmName.SHA1))
SHA512_224 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA512_224)
)
SHA512_256 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA512_256)
)
SHA224 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA224)
)
SHA256 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA256)
)
SHA384 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA384)
)
SHA512 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA512)
)
SHA3_224 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA3_224)
)
SHA3_256 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA3_256)
)
SHA3_384 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA3_384)
)
SHA3_512 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHA3_512)
)
SHAKE128 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHAKE128, block_size=64)
)
SHAKE256 = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.SHAKE256, block_size=64)
)
MD5 = SignatureAlgorithm(algorithm=HashAlgorithm(name=HashAlgorithmName.MD5))
BLAKE2b = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.BLAKE2b)
)
BLAKE2s = SignatureAlgorithm(
    algorithm=HashAlgorithm(name=HashAlgorithmName.BLAKE2s)
)
SM3 = SignatureAlgorithm(algorithm=HashAlgorithm(name=HashAlgorithmName.SM3))
