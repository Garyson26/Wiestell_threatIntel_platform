"""Trusted-hop derivation of the rate-limit bucket key.

The defect: `_client_ip` took the left-most `X-Forwarded-For` entry, which is whatever
the client sent, so rotating the header gave a fresh rate-limit bucket per request. That
defeated every `rate_limit()` call site with or without Redis — SECURITY_REVIEW.md
residual risk #5, which had recorded only the per-process cause.

The code lands now with `TRUSTED_PROXY_HOPS = 0`, so nothing changes behaviourally until
the count is measured against a deployed instance at Phase 6. These tests pin both the
inert default and the behaviour once it is set, so the value can be turned on with
confidence rather than with a redeploy-and-hope.
"""

import pytest

from app.api.deps import _client_ip
from app.config import settings


class _Client:
    def __init__(self, host):
        self.host = host


class _Request:
    """Minimal stand-in: `_client_ip` touches only `.headers` and `.client`."""

    def __init__(self, forwarded=None, peer="203.0.113.9"):
        self.headers = {} if forwarded is None else {"X-Forwarded-For": forwarded}
        self.client = _Client(peer) if peer is not None else None


@pytest.fixture
def hops(monkeypatch):
    def _set(count):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", count)
    return _set


class TestDefaultTrustsNothing:
    """The shipped default. Must stay inert until the hop count is measured."""

    def test_the_default_is_zero(self):
        """Not a style preference — a non-zero default is a bypass in development.

        The container is directly reachable locally, so trusting the header by default
        would let any dev-environment caller choose their own bucket.
        """
        assert settings.TRUSTED_PROXY_HOPS == 0

    def test_the_header_is_ignored_entirely_when_unset(self, hops):
        hops(0)
        request = _Request(forwarded="1.2.3.4, 5.6.7.8", peer="203.0.113.9")
        assert _client_ip(request) == "203.0.113.9"

    def test_a_spoofed_header_cannot_change_the_bucket_when_unset(self, hops):
        hops(0)
        peer = "203.0.113.9"
        buckets = {
            _client_ip(_Request(forwarded=forged, peer=peer))
            for forged in ("9.9.9.9", "1.1.1.1, 2.2.2.2", "", "not-an-ip")
        }
        assert buckets == {peer}, (
            "the forged header changed the bucket key, so rotating it would still "
            f"defeat the rate limit: {buckets}"
        )


class TestCountingFromTheRight:
    """The property that makes the header usable at all."""

    def test_one_trusted_hop_takes_the_last_entry(self, hops):
        hops(1)
        # Render's edge appends the address it observed, so with one trusted hop the
        # right-most entry is the real client.
        request = _Request(forwarded="198.51.100.7", peer="10.0.0.1")
        assert _client_ip(request) == "198.51.100.7"

    def test_a_client_supplied_prefix_is_ignored(self, hops):
        """The whole point. The left-most entries are attacker-controlled."""
        hops(1)
        request = _Request(forwarded="9.9.9.9, 8.8.8.8, 198.51.100.7", peer="10.0.0.1")
        assert _client_ip(request) == "198.51.100.7", (
            "an attacker-prepended entry was believed — this is the original defect"
        )

    def test_rotating_the_prefix_does_not_change_the_bucket(self, hops):
        hops(1)
        buckets = {
            _client_ip(_Request(forwarded=f"{forged}, 198.51.100.7", peer="10.0.0.1"))
            for forged in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4, 5.5.5.5")
        }
        assert buckets == {"198.51.100.7"}, buckets

    def test_two_trusted_hops_step_one_further_left(self, hops):
        hops(2)
        request = _Request(forwarded="9.9.9.9, 198.51.100.7, 10.0.0.2", peer="10.0.0.1")
        assert _client_ip(request) == "198.51.100.7"

    def test_the_left_most_entry_is_never_taken_implicitly(self, hops):
        """Guards against a regression to `split(",")[0]`.

        Swept across hop counts so no configuration reproduces the old behaviour while
        a client-supplied prefix is present.
        """
        forged = "9.9.9.9"
        for count in (1, 2, 3):
            hops(count)
            request = _Request(
                forwarded=f"{forged}, 198.51.100.7, 10.0.0.2, 10.0.0.3",
                peer="10.0.0.1",
            )
            assert _client_ip(request) != forged, f"hops={count} believed the client"


class TestFallsBackRatherThanReaching:
    """When the chain is shorter than configured, the request did not arrive as expected."""

    def test_a_short_header_falls_back_to_the_peer(self, hops):
        hops(3)
        request = _Request(forwarded="198.51.100.7", peer="203.0.113.9")
        assert _client_ip(request) == "203.0.113.9", (
            "with fewer entries than trusted hops the peer must win — reaching for the "
            "left-most entry would hand the choice back to the client"
        )

    def test_an_absent_header_falls_back_to_the_peer(self, hops):
        hops(1)
        assert _client_ip(_Request(forwarded=None, peer="203.0.113.9")) == "203.0.113.9"

    def test_an_empty_or_comma_only_header_falls_back(self, hops):
        hops(1)
        for junk in ("", "   ", ",", " , , "):
            assert _client_ip(_Request(forwarded=junk, peer="203.0.113.9")) == \
                "203.0.113.9", repr(junk)

    def test_no_client_and_no_usable_header_is_unknown(self, hops):
        """Bucketed together under one key rather than raising."""
        hops(0)
        assert _client_ip(_Request(forwarded=None, peer=None)) == "unknown"

    def test_whitespace_around_entries_is_stripped(self, hops):
        hops(1)
        request = _Request(forwarded="9.9.9.9 ,  198.51.100.7  ", peer="10.0.0.1")
        assert _client_ip(request) == "198.51.100.7"
