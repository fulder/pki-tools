import warnings
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

    --8<-- "docs/examples/chain.md"
    --8<-- "docs/examples/chain_from_cryptography.md"
    --8<-- "docs/examples/chain_from_uri.md"
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def check_chain(self):
        """
        Validate the chain (if it contains more than one certificate)
        checking expiration and signatures of all certificates in the chain

        .. deprecated::
            Use :meth:`validate_trust_path` instead, which only validates the
            trust path relevant to a specific certificate. This method
            validates all certificates in the chain, which causes false
            failures when the chain contains unrelated expired CAs.

        Raises:
            NotCompleteChain: When the chain contain only one not self-signed
                certificate
            CertExpired: If some certificate in the chain has expired
            InvalidSignedType: When the issuer has a non-supported type
            SignatureVerificationFailed: When the signature verification fails
        """
        warnings.warn(
            "check_chain() is deprecated, use validate_trust_path(signed) instead. "
            "check_chain() validates all certificates in the chain which causes "
            "false failures when the chain contains unrelated expired CAs.",
            DeprecationWarning,
            stacklevel=2,
        )
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

    def validate_trust_path(
        self,
        signed: [
            "Certificate",
            "CertificateRevocationList",
        ],
    ):
        """
        Validate only the trust path relevant to a given signed entity,
        checking expiration and signatures from the issuer up to the root.

        Unlike [check_chain][pki_tools.types.chain.Chain.check_chain] which
        validates every certificate in the chain, this method only validates
        the certificates that form the trust path for `signed`.

        Arguments:
            signed: The signed entity whose issuer path should be validated

        Raises:
            CertIssuerMissingInChain: When the issuer of the entity is missing
                in the chain
            CertExpired: If some certificate in the path has expired
            InvalidSignedType: When the issuer has a non-supported type
            SignatureVerificationFailed: When the signature verification fails
        """
        current = signed
        visited = set()

        while True:
            issuer_cert = self.get_issuer(current)

            if issuer_cert.serial_number in visited:
                break
            visited.add(issuer_cert.serial_number)

            # Self-signed root CAs are trust anchors
            is_root = issuer_cert.issuer == issuer_cert.subject

            # Check expiration only for non-root intermediates
            if not is_root:
                log = logger.bind(subject=issuer_cert.subject._string_dict())
                if issuer_cert.validity.not_after < datetime.now(
                    pytz.utc
                ) or issuer_cert.validity.not_before > datetime.now(pytz.utc):
                    log.error("Certificate expired")
                    raise CertExpired(
                        f"Certificate in chain with subject: "
                        f"'{issuer_cert.subject}' has expired"
                    )

            issuer_cert.verify_signature(current)

            if is_root:
                break

            current = issuer_cert

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
                [Certificate][pki_tools.types.certificate.Certificate] or
                [CertificateRevocationList][pki_tools.types.crl.CertificateRevocationList]
        Returns:
            The issuer of the `signed` entity

        Raises:
            CertIssuerMissingInChain: When the issuer of the entity is missing
                in the chain
        """
        cert_issuer = signed.issuer
        log = logger.bind(issuer=cert_issuer._string_dict())

        for next_chain_cert in self.certificates:
            if cert_issuer == next_chain_cert.subject:
                log.trace("Found issuer cert in chain")
                return next_chain_cert

        raise CertIssuerMissingInChain()
