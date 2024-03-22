from pki_tools import RSAKeyPair, RSAPublicKey, RSAPrivateKey

key_pair = RSAKeyPair(
    public_key=RSAPublicKey.from_file("public.pem"),
    private_key=RSAPrivateKey.from_file("private.pem"),
)

print(key_pair)
