from pki_tools import Chain


def test_chain_from_uri():
    Chain.from_uri("https://letsencrypt.org/certs/lets-encrypt-r3.pem")