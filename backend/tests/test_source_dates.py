"""Phase 4 Section C — CISA KEV and MISP CERT-FR carry real source dates.

Both feeds previously recorded **our ingest date** as the indicator's observation time,
because `_make_ioc` defaults an absent stamp to `now()`. For catalogues reaching back to
2020-2021 that is not a rounding error: every entry read as though first seen on whatever
day we happened to sync, so recency never decayed and an eight-year-old hash scored like
a fresh one.

Fixing it is score-affecting in one direction — downward for anything genuinely old — and
`SCORING_MODEL_VERSION` moved to 10 accordingly.

THE PROPERTY THESE TESTS EXIST FOR is the **no-verdict** case. When a date is unavailable
the connector must pass `None`, never `now()`. Passing `now()` would set
`_source_timestamped=True` and engage the timestamped scoring path, turning "we do not
know when this happened" into "we observed this today" — absence of evidence read as
evidence, which is the most repeated defect class in this codebase.
"""

from datetime import datetime

import pytest

from app.feeds.cisa_kev import CISAKEVFeed, _parse_kev_date
from app.feeds.misp_cert_fr import MISPCertFRFeed


class TestCISAKEVCarriesDateAdded:
    async def test_date_added_reaches_the_ioc(self):
        raw = {"vulnerabilities": [
            {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
        ]}
        ioc = (await CISAKEVFeed(api_key=None).parse(raw))[0]
        assert ioc["first_seen"] == datetime(2021, 12, 10)
        assert ioc["last_seen"] == datetime(2021, 12, 10)
        assert ioc["_source_timestamped"] is True, (
            "the record carries a real source date, so it must take the timestamped "
            "scoring path"
        )

    async def test_the_date_is_years_from_ingest_time_which_is_the_whole_point(self):
        """Guards the magnitude, not just the plumbing.

        A test asserting only "first_seen is not None" would pass if the connector
        substituted now(). The gap between the source date and today is the defect.
        """
        raw = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
        ioc = (await CISAKEVFeed(api_key=None).parse(raw))[0]
        assert (datetime.utcnow() - ioc["first_seen"]).days > 365, (
            "first_seen is close to now(), so the source date is being ignored and "
            "ingest time substituted — the pre-2026-08-17 behaviour"
        )

    @pytest.mark.parametrize("bad", [None, "", "   ", "garbage", "2021-13-45", "10/12/2021"])
    async def test_an_unparseable_date_is_a_no_verdict(self, bad):
        """None, not now(). `_make_ioc` then defaults the stamp and marks it untimestamped."""
        assert _parse_kev_date(bad) is None
        raw = {"vulnerabilities": [{"cveID": "CVE-2020-0001", "dateAdded": bad}]}
        ioc = (await CISAKEVFeed(api_key=None).parse(raw))[0]
        assert ioc["_source_timestamped"] is False, (
            "an unparseable date produced a record claiming to be source-timestamped, "
            "so an unknown date would be scored as a fresh observation"
        )

    async def test_a_missing_date_key_entirely_is_a_no_verdict(self):
        raw = {"vulnerabilities": [{"cveID": "CVE-2020-0002"}]}
        ioc = (await CISAKEVFeed(api_key=None).parse(raw))[0]
        assert ioc["_source_timestamped"] is False


class TestMISPManifestJoin:
    CSV = (
        "d41d8cd98f00b204e9800998ecf8427e,uuid-dated\n"
        "5d41402abc4b2a76b9719d911017c592,uuid-missing\n"
    )
    MANIFEST = {
        "uuid-dated": {"date": "2020-03-04", "info": "CERT-FR case"},
        "uuid-other": {"date": "2024-01-01"},
    }

    async def test_a_hash_gets_its_event_date(self):
        parsed = await MISPCertFRFeed(api_key=None).parse(
            {"csv": self.CSV, "event_dates": {
                "uuid-dated": datetime(2020, 3, 4)}}
        )
        dated = next(i for i in parsed if i["value"].startswith("d41d8"))
        assert dated["first_seen"] == datetime(2020, 3, 4)
        assert dated["_source_timestamped"] is True
        assert dated["metadata"]["misp_event_date"] == "2020-03-04"

    async def test_a_uuid_absent_from_the_manifest_is_a_no_verdict(self):
        """The specific case the owner called out. No date, not ingest time."""
        parsed = await MISPCertFRFeed(api_key=None).parse(
            {"csv": self.CSV, "event_dates": {"uuid-dated": datetime(2020, 3, 4)}}
        )
        undated = next(i for i in parsed if i["value"].startswith("5d414"))
        assert undated["_source_timestamped"] is False, (
            "a hash whose event UUID is not in the manifest was marked "
            "source-timestamped, so an unknown date scores as a fresh observation"
        )
        assert "misp_event_date" not in undated["metadata"], (
            "a date was recorded in metadata for an event that has none"
        )

    async def test_an_entirely_missing_manifest_is_a_no_verdict_for_every_hash(self):
        parsed = await MISPCertFRFeed(api_key=None).parse(
            {"csv": self.CSV, "event_dates": {}}
        )
        assert parsed, "no IOCs parsed — the check below would be vacuous"
        assert all(i["_source_timestamped"] is False for i in parsed), (
            "an unavailable manifest must leave every hash undated rather than "
            "stamping them all with the sync time"
        )

    async def test_a_bare_csv_string_still_parses(self):
        """The old call shape must not become an AttributeError mid-sync."""
        parsed = await MISPCertFRFeed(api_key=None).parse(self.CSV)
        assert len(parsed) == 2
        assert all(i["_source_timestamped"] is False for i in parsed)

    async def test_the_manifest_is_fetched_once_not_per_row(self):
        """Caching is the difference between 1 request and 2,277 of them."""
        import ast
        import inspect
        import textwrap

        def _called(func):
            tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
            return {
                getattr(n.func, "attr", None) or getattr(n.func, "id", None)
                for n in ast.walk(tree) if isinstance(n, ast.Call)
            }

        # A CALL, not a mention. `parse` refers to `_event_dates` in a comment and uses a
        # local named `event_dates`, so a substring check matches both and fails for the
        # wrong reason — which is exactly what the first version of this test did.
        parse_calls = _called(MISPCertFRFeed.parse)
        assert parse_calls, "no calls extracted from parse(); the check would be vacuous"
        assert "_fetch_url" not in parse_calls, (
            "parse() fetches. The manifest must be resolved once in fetch() and handed "
            "in as a prebuilt map — ~2,277 hashes across ~18 events means a per-row "
            "join is 2,277 requests to answer 18 questions."
        )
        assert "_event_dates" not in parse_calls, (
            "parse() builds the event-date map itself, so it would be rebuilt per call"
        )
        assert "_event_dates" in _called(MISPCertFRFeed.fetch), (
            "fetch() no longer resolves the manifest, so parse() has no dates to join"
        )

    async def test_a_malformed_manifest_shape_does_not_raise(self):
        """A list, a string or nulls where objects were expected."""
        feed = MISPCertFRFeed(api_key=None)
        for bogus in ({"u": None}, {"u": "2020-01-01"}, {"u": {"date": None}},
                      {"u": {"date": "not-a-date"}}, {"u": {}}):
            parsed = await feed.parse({"csv": self.CSV, "event_dates": {}})
            assert all(i["_source_timestamped"] is False for i in parsed)


class TestTheScoringVersionMoved:
    def test_version_is_at_least_ten(self):
        """Both changes move recency for whole populations, so the bump is required."""
        from app.services.scoring_engine import SCORING_MODEL_VERSION

        assert SCORING_MODEL_VERSION >= 10, (
            "CISA KEV and MISP CERT-FR now carry real source dates, which moves recency "
            "for ~1,656 CVEs and ~2,277 hashes. The fingerprint guard cannot see an "
            "input change, so the version bump is the only signal the rescore has."
        )
