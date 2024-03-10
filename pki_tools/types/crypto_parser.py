import abc
from enum import Enum
from typing import Type, TypeVar, Dict

from pydantic import BaseModel

from pki_tools.exceptions import (
    MissingInit,
)

from loguru import logger

CryptoObject = TypeVar("CryptoObject")


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
    Describes the encoding used for writing/reading from/to files
    """

    PEM = "pem_string"
    DER = "der_bytes"


class IoCryptoParser(CryptoParser, abc.ABC):
    """
    Extending the CryptoParser with abstract functions to load
    and write the implementing class in different formats and to/from files
    """

    @property
    @abc.abstractmethod
    def der_bytes(self) -> bytes:
        """
        Returns the DER bytes of the object

        Returns:
            The DER bytes.
        """

    @property
    @abc.abstractmethod
    def pem_bytes(self) -> bytes:
        """
        Returns the PEM bytes of the object

        Returns:
            The PEM bytes.
        """

    @classmethod
    @abc.abstractmethod
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

    @classmethod
    @abc.abstractmethod
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
