from pki_tools import DSAKeyPair, DSAPrivateKey, DSAPublicKey

key_pair = DSAKeyPair(
    public_key=DSAPublicKey.from_file("public.pem"),
    private_key=DSAPrivateKey.from_file("private.pem"),
)

print(key_pair)
