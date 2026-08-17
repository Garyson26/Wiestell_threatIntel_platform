"""Direct assertions for `utils/ioc_validator`, which had none.

It is called from `api/ioc.py` (two sites) and from `feed_ingestion`, so it sits on the
ingestion hot path and on user-supplied IOC creation. It was exercised indirectly by both
and asserted by neither — the property PROJECT_SUMMARY item 19 called the worst on that
list: **a loosened check would pass every existing test.**

So these are written to fail on LOOSENING, not just on breakage. Most assert a REJECTION,
because that is the direction a careless edit moves: widening a regex to accept a value
someone reported as a false negative is a one-character change, and nothing else in the
suite would notice.

The behaviour pinned here is the behaviour as measured on 2026-08-04. It is already sound —
every hostile value probed was rejected — so this is characterization rather than repair.
"""

import pytest

from app.utils.ioc_validator import (
    detect_ioc_type,
    get_hash_type,
    normalize_ioc,
    validate_ioc,
)


class TestUnknownTypesFailClosed:
    """The default branch. An unrecognised type must never validate."""

    @pytest.mark.parametrize("ioc_type", [
        "", "unknown", "ssl", "IP", "Domain", "hash ", "../../etc/passwd", "None",
    ])
    def test_an_unrecognised_type_rejects_everything(self, ioc_type):
        assert validate_ioc(ioc_type, "8.8.8.8") is False
        assert validate_ioc(ioc_type, "anything at all") is False

    def test_the_comparison_is_case_sensitive(self):
        """`"IP"` is not `"ip"`. Loosening this would let a mis-cased type bypass the
        specific check and fall into whichever branch matched next."""
        assert validate_ioc("ip", "8.8.8.8") is True
        assert validate_ioc("IP", "8.8.8.8") is False


class TestNothingWithWhitespaceOrControlCharactersValidates:
    """Values reach a database, a CSV export and an AI prompt.

    CSV formula injection is separately escaped in `api/ioc.py`, and the AI prompt is
    separately fenced — but a value containing a newline should never get that far, and
    these are the shapes a widened regex would start admitting.
    """

    @pytest.mark.parametrize("value", [
        "evil.com\nrm -rf /",
        "evil.com\r\nSet-Cookie: x=y",
        "ev il.com",
        "evil\tcom.example",
        "evil\x00.com",
    ])
    def test_domains_with_EMBEDDED_whitespace_or_nulls_are_rejected(self, value):
        """Embedded, not trailing. The distinction is the whole point.

        My first version asserted `"evil.com\t"` was rejected, and it is NOT: `.strip()`
        removes a trailing tab exactly as it removes trailing spaces, so that is padding
        rather than injection. The expectation was wrong, not the code.

        What matters is that whitespace INSIDE the value never validates, and that
        `normalize_ioc` strips with the same call — so the value stored is the value
        checked, and there is no window where a newline survives into the database.
        """
        assert validate_ioc("domain", value) is False

    @pytest.mark.parametrize("value", [
        "http://x.com/\nInjected: header",
        "http://x.com/ with space",
    ])
    def test_urls_with_embedded_whitespace_are_rejected(self, value):
        assert validate_ioc("url", value) is False

    @pytest.mark.parametrize("padded", [
        "  evil.com  ", "evil.com\t", "evil.com\n", "\r\nevil.com", "\tevil.com\t",
    ])
    def test_surrounding_whitespace_of_ANY_kind_is_stripped_not_rejected(self, padded):
        """Feeds pad values, and a tab or newline at the edge is padding like a space.

        Paired with the normalisation assertion so the two cannot drift: if `validate_ioc`
        stripped and `normalize_ioc` did not, a value could pass validation and then be
        stored with the whitespace still attached.
        """
        assert validate_ioc("domain", padded) is True
        assert normalize_ioc(padded, "domain") == "evil.com"

    def test_hash_padding_is_stripped_too(self):
        assert validate_ioc("hash", "  " + "a" * 32 + "  ") is True


class TestUrlSchemeIsRestricted:
    """Only http and https. A URL is rendered in the dashboard and can be clicked."""

    @pytest.mark.parametrize("value", [
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "//example.com/x",
        "http://",
        "https://",
    ])
    def test_non_http_schemes_and_empty_authorities_are_rejected(self, value):
        assert validate_ioc("url", value) is False

    @pytest.mark.parametrize("value", [
        "http://example.com",
        "https://example.com/path?q=1",
        "HTTPS://EXAMPLE.COM",
    ])
    def test_http_and_https_are_accepted(self, value):
        assert validate_ioc("url", value) is True


class TestHashLengthsAreExact:
    """32, 40 or 64 hex. Off-by-one lengths must not slip through."""

    @pytest.mark.parametrize("length,valid", [
        (31, False), (32, True), (33, False),
        (39, False), (40, True), (41, False),
        (63, False), (64, True), (65, False),
    ])
    def test_only_md5_sha1_and_sha256_lengths_validate(self, length, valid):
        assert validate_ioc("hash", "a" * length) is valid

    def test_non_hex_characters_are_rejected(self):
        assert validate_ioc("hash", "g" * 32) is False
        assert validate_ioc("hash", "z" + "a" * 31) is False

    def test_case_is_accepted_both_ways(self):
        assert validate_ioc("hash", "ABCDEF0123456789ABCDEF0123456789") is True
        assert validate_ioc("hash", "abcdef0123456789abcdef0123456789") is True

    @pytest.mark.parametrize("length,expected", [
        (32, "md5"), (40, "sha1"), (64, "sha256"), (33, None),
    ])
    def test_get_hash_type_agrees_with_validate(self, length, expected):
        assert get_hash_type("a" * length) == expected


class TestIpAcceptsCidrDeliberately:
    """`ip_network(strict=False)` is a second branch, not an accident.

    Feeds publish blocklists as CIDR ranges, so rejecting them would drop real indicators.
    Pinned so the branch is not removed as apparent dead code.
    """

    @pytest.mark.parametrize("value", [
        "8.8.8.8", "1.2.3.0/24", "1.2.3.4/32", "2001:db8::1", "2001:db8::/32",
    ])
    def test_plain_addresses_and_networks_validate(self, value):
        assert validate_ioc("ip", value) is True

    @pytest.mark.parametrize("value", [
        "999.999.999.999", "1.2.3", "1.2.3.4.5", "not-an-ip", "1.2.3.0/99", "",
    ])
    def test_malformed_addresses_are_rejected(self, value):
        assert validate_ioc("ip", value) is False


class TestCveShape:
    @pytest.mark.parametrize("value,valid", [
        ("CVE-2021-44228", True),
        ("cve-2021-44228", True),        # case-insensitive by design
        ("CVE-2021-4", False),           # sequence must be >= 4 digits
        ("CVE-21-44228", False),         # year must be 4 digits
        ("CVE-2021-442280000", True),    # long sequences are real
        ("NOT-2021-44228", False),
    ])
    def test_cve_pattern(self, value, valid):
        assert validate_ioc("cve", value) is valid


class TestDetectionOrderIsStable:
    """`detect_ioc_type` returns the FIRST match, so ordering is a contract.

    A 32-hex string is a valid md5 and could also look like a label; hashes are checked
    first. Reordering the checks would silently retype existing indicators.
    """

    @pytest.mark.parametrize("value,expected", [
        ("CVE-2021-44228", "cve"),
        ("a" * 32, "hash"),
        ("a" * 40, "hash"),
        ("a" * 64, "hash"),
        ("user@example.com", "email"),
        ("https://example.com/x", "url"),
        ("8.8.8.8", "ip"),
        ("1.2.3.0/24", "ip"),
        ("example.com", "domain"),
        ("not a valid anything!", None),
        ("", None),
    ])
    def test_detection(self, value, expected):
        assert detect_ioc_type(value) == expected

    def test_an_unrecognisable_value_returns_None_rather_than_guessing(self):
        for value in ("...", "@@@", "http://", "1.2.3"):
            assert detect_ioc_type(value) is None, value


class TestNormalisationInvariants:
    """These two properties are what dedup and re-validation depend on."""

    @pytest.mark.parametrize("ioc_type,value", [
        ("domain", "EVIL.COM."),
        ("domain", "  Evil.Com  "),
        ("url", "https://example.com/path/"),
        ("hash", "ABCDEF0123456789ABCDEF0123456789"),
        ("email", "User@Example.COM"),
        ("ip", "8.8.8.8"),
        ("cve", "cve-2021-44228"),
        ("ssl_cert", "A" * 40),
    ])
    def test_normalisation_is_idempotent(self, ioc_type, value):
        """`UNIQUE(type, value)` is the dedup key, so normalising twice must equal once.

        If it were not idempotent, the same indicator could be stored under two spellings
        depending on how many times it had passed through — inflating `source_count` and
        therefore the diversity term of the score.
        """
        once = normalize_ioc(value, ioc_type)
        assert normalize_ioc(once, ioc_type) == once

    @pytest.mark.parametrize("ioc_type,value", [
        ("domain", "EVIL.COM"),
        ("url", "https://example.com/path/"),
        ("hash", "ABCDEF0123456789ABCDEF0123456789"),
        ("email", "User@Example.COM"),
        ("ip", "8.8.8.8"),
        ("cve", "cve-2021-44228"),
    ])
    def test_a_valid_value_is_still_valid_after_normalisation(self, ioc_type, value):
        """Ingestion validates, then normalises, then stores.

        If normalisation could produce something the validator rejects, the database would
        hold values that fail their own check — invisible until something re-validated.
        """
        assert validate_ioc(ioc_type, value) is True
        assert validate_ioc(ioc_type, normalize_ioc(value, ioc_type)) is True

    def test_normalisation_does_not_alter_an_unknown_type(self):
        assert normalize_ioc("  SomeValue  ", "unknown") == "SomeValue"

    def test_a_cidr_ip_survives_normalisation(self):
        """`normalize_ioc` uses `ip_address`, which raises on CIDR, and falls through.

        The value is left as-is rather than mangled — pinned because the `except ValueError:
        pass` looks like an oversight and is what keeps CIDR values intact.
        """
        assert normalize_ioc("1.2.3.0/24", "ip") == "1.2.3.0/24"
        assert validate_ioc("ip", normalize_ioc("1.2.3.0/24", "ip")) is True
