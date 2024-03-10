import abc
import importlib
import re
from enum import Enum
from typing import Type, TypeVar, Dict

from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel

from pki_tools.exceptions import (
    MissingInit,
    LoadError,
)

from loguru import logger

CryptoObject = TypeVar("CryptoObject")


X509_MODULE = importlib.import_module("cryptography.x509")


class CryptoParser(BaseModel, abc.ABC):
    """
    CryptoParser is an abstract class used by all the types
    parsing cryptography objects into [pki_tools][pki_tools.types.certificate]
    pydantic classes.
    """

    _x509_obj: CryptoObject

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        if "_x509_obj" not in kwargs:
            try:
                self._x509_obj = self._to_cryptography()
            except MissingInit:
                logger.trace("Can't create crypto object before init")

    @classmethod
    @abc.abstractmethod
    def from_cryptography(
        cls: Type["CryptoParser"], crypto_obj: CryptoObject
    ) -> "CryptoParser":
        """
        Parses a cryptography x509 object into a
        [CryptoParser][pki_tools.types.crypto_parser.CryptoParser]

        Arguments:
             crypto_obj: The cryptography object

        Returns:
            CryptoParser object
        """

    @abc.abstractmethod
    def _to_cryptography(self) -> CryptoObject:
        """
        Creates a x509 cryptography object from this class

        Returns: A x509 cryptography object
        """

    @abc.abstractmethod
    def _string_dict(self) -> Dict[str, str]:
        """
        Creates a dict representation of the object

        Returns: A dict containing all the keys in the CryptoParser
        """


class InitCryptoParser(CryptoParser, abc.ABC):
    """
    Extends the CryptoParser into an object that requires initialization
    before it can be used (while created as a
    [pki_tools][pki_tools.types.certificate] object and not loaded from
    cryptography). This can, for example, be a Certificate that needs
    to be signed with a KeyPair containing the private key.

    Attempt to e.g. dumping a certificate to a PEM string without using the
    sign (init) function first will result in a
    [MissingInit][pki_tools.exceptions.MissingInit] exception.
    """

    _init_func: str = "sign"

    @property
    def _crypto_object(self) -> CryptoObject:
        if not hasattr(self, "_x509_obj") or self._x509_obj is None:
            init_func = f"{self.__class__.__name__}.{self._init_func}"
            raise MissingInit(f"Please use the {init_func} first")

        return self._x509_obj


class Encoding(Enum):
    """
    Describes the encoding used for writing/reading
    [IoCryptoParser][pki_tools.types.crypto_parser.IoCryptoParser]
    objects.
    """

    PEM = "pem_string"
    DER = "der_bytes"


class CryptoConfig(BaseModel):
    load_pem: str
    load_der: str
    pem_regexp: re.Pattern


class IoCryptoParser(CryptoParser, abc.ABC):
    """
    Extending the CryptoParser with abstract functions to load
    and write the implementing class in different formats and to/from files
    """

    @classmethod
    def from_pem_string(
        cls: Type["IoCryptoParser"], pem: str
    ) -> "IoCryptoParser":
        """
        Loads the object from a PEM string

        Arguments:
            pem: The PEM encoded object in string format

        Returns:
            A created object from the PEM
        """
        cfg = cls._crypto_func_names()

        if not isinstance(pem, str):
            logger.bind(pem=pem).debug("PEM parameter is not a string")
            raise LoadError()

        pem = re.sub(r"\n\s*", "\n", pem)

        if not re.match(cfg.pem_regexp, pem):
            logger.bind(pem=pem).debug("PEM parameter has invalid format")
            raise LoadError()

        crypto_obj = getattr(X509_MODULE, cfg.load_pem)(pem.encode())
        return cls.from_cryptography(crypto_obj)

    @classmethod
    def from_der_bytes(
        cls: Type["IoCryptoParser"], der: bytes
    ) -> "IoCryptoParser":
        """
        Loads the object from DER bytes

        Arguments:
            der: The DER encoded object

        Returns:
            A created object from the DER bytes
        """
        cfg = cls._crypto_func_names()
        crypto_obj = getattr(X509_MODULE, cfg.load_der)(der)
        return cls.from_cryptography(crypto_obj)

    @classmethod
    def from_file(
        cls, file_path: str, encoding: Encoding = Encoding.PEM
    ) -> "IoCryptoParser":
        """
        Reads a file containing one PEM into the object

        Arguments:
            file_path: The path to the file (can be relative the caller or
                absolute)
            encoding: The encoding to use for the dumped data
        Returns:
             The Certificate loaded from the specified file
        """

        with open(file_path, "r") as f:
            data = f.read()

        return getattr(cls, f"from_{encoding.value}")(data)

    @property
    def der_bytes(self) -> bytes:
        """
        Returns the DER bytes of the object

        Returns:
            The DER bytes.
        """
        return self._crypto_object.public_bytes(serialization.Encoding.DER)

    @property
    def pem_bytes(self) -> bytes:
        """
        Returns the PEM bytes of the object

        Returns:
            The PEM bytes.
        """
        return self._crypto_object.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    @property
    def pem_string(self) -> str:
        """
        Returns:
            PEM decoded into a string
        """
        return self.pem_bytes.decode()

    def to_file(
        self, file_path: str, encoding: Encoding = Encoding.PEM
    ) -> None:
        """
        Saves the object with specified encoding to the specified file,
        creating it if it doesn't exist.

        Args:
            file_path: The path to the file (can be relative the caller or
                absolute)
            encoding: The encoding to use for the dumped data
        """
        with open(file_path, "w") as f:
            f.write(getattr(self, encoding.value))

    @classmethod
    @abc.abstractmethod
    def _crypto_func_names(cls) -> CryptoConfig:
        pass
