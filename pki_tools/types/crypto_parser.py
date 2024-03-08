import abc
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
