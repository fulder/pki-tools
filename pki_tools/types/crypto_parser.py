import abc
from typing import Type, TypeVar, Dict

from pydantic import BaseModel

from pki_tools.exceptions import (
    MissingInit,
)

from loguru import logger

CryptoObject = TypeVar("CryptoObject")


class CryptoParser(BaseModel, abc.ABC):
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
        cls: Type["CryptoParser"], crypto_obj
    ) -> "CryptoParser":
        """
        Parses a cryptography x509 object into a CryptoParser

        Arguments:
             crypto_obj --The cryptography object
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
    _init_func: str = "sign"

    @property
    def _crypto_object(self) -> CryptoObject:
        if not hasattr(self, "_x509_obj") or self._x509_obj is None:
            init_func = f"{self.__name__}.{self._init_func}"
            raise MissingInit(f"Please use the {init_func} first")

        return self._x509_obj
