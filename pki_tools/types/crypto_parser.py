import abc
from typing import Type, TypeVar, Dict

from pydantic import BaseModel

from pki_tools.exceptions import MissingPrivateKey, MissingOcspCert

from loguru import logger

CryptoObject = TypeVar("CryptoObject")


class CryptoParser(BaseModel, abc.ABC):
    _x509_obj: CryptoObject

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        if "_x509_obj" not in kwargs:
            try:
                self._x509_obj = self._to_cryptography()
            except MissingPrivateKey:
                logger.trace(
                    "Can't create crypto object before setting private key"
                )
            except MissingOcspCert:
                logger.trace(
                    "Can't create crypto object before setting ocsp cert"
                )

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
