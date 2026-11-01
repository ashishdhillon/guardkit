from guardkit import PIIGuard
from guardkit.pii import luhn_valid, verhoeff_check_digit, verhoeff_valid


def _aadhaar(prefix11="23456789012"):
    return prefix11 + verhoeff_check_digit(prefix11)


def rules(text, **kw):
    return sorted(f.rule for f in PIIGuard(**kw).scan(text))


def test_verhoeff_roundtrip():
    n = _aadhaar()
    assert verhoeff_valid(n)
    bad = n[:-1] + str((int(n[-1]) + 1) % 10)
    assert not verhoeff_valid(bad)


def test_aadhaar_detected_only_when_checksum_valid():
    n = _aadhaar()
    spaced = f"{n[:4]} {n[4:8]} {n[8:]}"
    assert rules(f"id {spaced}") == ["aadhaar"]
    bad = n[:-1] + str((int(n[-1]) + 1) % 10)
    assert "aadhaar" not in rules(f"id {bad}")


def test_card_luhn():
    assert luhn_valid("4111111111111111")
    assert rules("pay 4111 1111 1111 1111 now") == ["card"]
    assert rules("pay 4111 1111 1111 1112 now") == []


def test_pan():
    assert rules("PAN ABCPD1234E") == ["pan"]
    assert rules("PAN ABCZD1234E") == []        # invalid 4th letter
    assert rules("abcpd1234e") == []            # lowercase is not a PAN


def test_email_and_phone():
    assert rules("a.b+c@example.co.in") == ["email"]
    assert rules("call +91 98765 43210") == ["phone"]
    assert rules("call 9876543210") == ["phone"]
    assert rules("call +44 20 7946 0958") == ["phone"]
    assert rules("order 12345") == []


def test_ipv4():
    assert rules("host 192.168.1.10 up") == ["ipv4"]
    assert rules("version 1.2.3.4.5") == []


def test_type_filter_and_unknown_type():
    assert rules("a@b.com 9876543210", types=["email"]) == ["email"]
    try:
        PIIGuard(types=["passport"])
        assert False
    except ValueError:
        pass


def test_ssn_and_pincode():
    assert rules("ssn 123-45-6789") == ["ssn"]
    assert rules("ssn 000-12-3456") == []
    assert rules("ssn 666-12-3456") == []
    assert rules("PIN code 110001") == ["pincode"]
    assert rules("pincode: 560034") == ["pincode"]
    assert rules("order 110001") == []          # no cue word, not flagged


def test_opt_in_name_and_address():
    assert rules("Dr. Anita Sharma attended", types=["name"]) == ["name"]
    assert rules("my name is Ravi Kumar", types=["name"]) == ["name"]
    assert rules("Flat 12B, Gandhi Nagar, Delhi", types=["address"]) == ["address"]
    assert rules("The dr. said hi", types=["name"]) == []
    assert rules("Dr. Anita Sharma, Flat 12B, Gandhi Nagar") == []   # not on by default
    r = PIIGuard(types=["name"]).scan("Thanks Mr. Rao")
    assert [f.text for f in r] == ["Mr. Rao"]
