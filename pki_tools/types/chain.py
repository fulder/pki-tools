from datetime import datetime

import pytz
from loguru import logger
from pydantic import ConfigDict

from pki_tools.exceptions import (
    NotCompleteChain,
    CertExpired,
    CertIssuerMissingInChain,
)
from pki_tools.types.certificate import Certificate
from pki_tools.types.certificates import Certificates
from pki_tools.types.crl import CertificateRevocationList


class Chain(Certificates):
    """
    Chain holds a list of certificates in a
    [chain of trust](https://en.wikipedia.org/wiki/Chain_of_trust)

    Examples:
    From File::
        chain = Chain.from_file("/path/to/chain.pem")
    From PEM::
        pem_string="-----BEGIN CERTIFICATE-----...."
        chain = Chain.from_pem_string(pem_string)
    From URI::
        chain = Chain.from_uri("https://chain.domain/chain.pem")
    Using Chain::
        cert: Certificate = ...
        chain.check_chain()
        chain.get_issuer(cert)
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def check_chain(self):
        """
        Validate the chain (if it contains more than one certificate)
        checking expiration and signatures of all certificates in the chain

        Raises:
            [exceptions.NotCompleteChain](https://pki-tools.fulder.dev/pki_tools/exceptions/#notcompletechain)
            -- When the chain contain only one not self-signed certificate

            [exceptions.CertExpired](https://pki-tools.fulder.dev/pki_tools/exceptions/#certexpired)
            -- If some certificate in the chain has expired

            [exceptions.InvalidSignedType](https://pki-tools.fulder.dev/pki_tools/exceptions/#invalidsignedtype)
            -- When the issuer has a non-supported type

            [exceptions.SignatureVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#signatureverificationfailed)
            -- When the signature verification fails
        """
        if len(self.certificates) == 1:
            if self.certificates[0].issuer == self.certificates[0].subject:
                logger.debug(
                    "Chain contains only one self signed cert, "
                    "nothing to check"
                )
                return
            else:
                raise NotCompleteChain()

        for cert in self.certificates:
            log = logger.bind(subject=cert.subject._string_dict())
            if cert.validity.not_after < datetime.now(
                pytz.utc
            ) or cert.validity.not_before > datetime.now(pytz.utc):
                log.error("Certificate expired")
                raise CertExpired(
                    f"Certificate in chain with subject: '{cert.subject}' "
                    f"has expired"
                )

            issuer = self.get_issuer(cert)
            issuer.verify_signature(cert)

    def get_issuer(
        self,
        signed: [
            Certificate,
            CertificateRevocationList,
        ],
    ) -> Certificate:
        """
        Returns the issuer of a signed entity

        Arguments:
            signed: The signed entity can either be a
            [Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
            [CertificateRevocationList](https://pki-tools.fulder.dev/pki_tools/types/#certificaterevocationlist)
        Returns:
            The
            [Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
            representing the issuer of the `signed` entity
        Raises:
            [CertIssuerMissingInChain](https://pki-tools.fulder.dev/pki_tools/exceptions/#certissuermissinginchain)
            -- When the issuer of the entity is missing in the chain
        """
        cert_issuer = signed.issuer
        log = logger.bind(issuer=cert_issuer._string_dict())

        for next_chain_cert in self.certificates:
            if cert_issuer == next_chain_cert.subject:
                log.trace("Found issuer cert in chain")
                return next_chain_cert

        raise CertIssuerMissingInChain()
