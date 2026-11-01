from guardkit import SecretsGuard


def rules(text):
    return sorted(f.rule for f in SecretsGuard().scan(text))


# fake credentials are assembled at runtime so no scanner flags this file
def test_known_formats():
    assert rules("key " + "AKIA" + "ABCDEFGHIJKLMNOP") == ["aws_access_key"]
    assert rules("tok " + "ghp_" + "a" * 36) == ["github_token"]
    assert rules("k " + "AIza" + "B" * 35) == ["google_api_key"]
    assert rules("-----BEGIN " + "PRIVATE KEY-----") == ["private_key"]
    assert rules("sk_" + "test_" + "x1Y2z3A4b5C6d7E8f9") == ["stripe_key"]


def test_generic_assignment_needs_entropy():
    assert rules("api_key = 'q8Zr3Kx9Lm2Pw7Vt5Hn4Bj6'") == ["generic_assignment"]
    assert rules("password: aaaaaaaaaaaaaaaaaaaa") == []
    assert rules("the token is described in the docs") == []
