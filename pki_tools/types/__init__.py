import yaml

from .certificates import Certificates
from .certificate import Certificate, Validity
from .chain import Chain
from .crl import CertificateRevocationList
from .csr import CertificateSigningRequest
from .extensions import Extensions
from .name import Name
from .enums import RevokeMode
from .key_pair import (
    CryptoKeyPair,
    CryptoPublicKey,
    CryptoPrivateKey,
    DSAKeyPair,
    DSAPublicKey,
    DSAPrivateKey,
    RSAKeyPair,
    RSAPrivateKey,
    RSAPublicKey,
    EllipticCurveKeyPair,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    EllipticCurveName,
    Ed25519KeyPair,
    Ed25519PublicKey,
    Ed25519PrivateKey,
    Ed448KeyPair,
    Ed448PrivateKey,
    Ed448PublicKey,
)
from .signature_algorithm import (
    SignatureAlgorithm,
    HashAlgorithm,
    HashAlgorithmName,
    SHA1,
    SHA512_224,
    SHA512_256,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256,
    MD5,
    BLAKE2b,
    BLAKE2s,
    SM3,
)

from .ocsp import (
    OCSPRequest,
    OCSPResponse,
    OcspResponseStatus,
    OcspCertificateStatus,
)


MAX_YAML_LEN = 80


def str_presenter(dumper, data):
    if len(data) > MAX_YAML_LEN:
        chunks = [
            data[i : i + MAX_YAML_LEN]
            for i in range(0, len(data), MAX_YAML_LEN)
        ]

        data = "\n".join(chunks)
        return dumper.represent_scalar(
            "tag:yaml.org,2002:str", data, style="|"
        )
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
