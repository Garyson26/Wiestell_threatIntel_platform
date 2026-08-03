"""Feed connector registry and parsing."""

import importlib

import pytest
from pydantic import ValidationError

from app.feeds.cisa_kev import CISAKEVFeed
from app.feeds.ecrimelabs import ECrimeLabsCVEFeed
from app.feeds.misp_cert_fr import MISPCertFRFeed
from app.schemas.feed import FeedCreate, FeedUpdate
from app.services.feed_ingestion import _normalize_batch
from app.services.feed_scheduler import FEED_CONNECTORS

NEW_CONNECTORS = [CISAKEVFeed, ECrimeLabsCVEFeed, MISPCertFRFeed]


class TestRegistry:
    @pytest.mark.parametrize("slug", sorted(FEED_CONNECTORS))
    def test_every_registered_slug_resolves(self, slug):
        """A dangling registry entry fails at sync time with AttributeError."""
        module_path, class_name = FEED_CONNECTORS[slug].rsplit(".", 1)
        connector = getattr(importlib.import_module(module_path), class_name)
        assert connector is not None

    def test_mitre_attack_is_not_registered_as_a_feed(self):
        """It exposes load_attack_data() for seed_mitre.py, not a BaseFeed class."""
        assert "mitre-attack" not in FEED_CONNECTORS

    @pytest.mark.parametrize("connector", NEW_CONNECTORS)
    def test_connector_declares_the_attributes_the_pipeline_reads(self, connector):
        instance = connector(api_key=None)      # scheduler calls connector(api_key=...)
        assert instance.slug and instance.slug != "unknown"
        assert instance.feed_type in ("api", "csv", "stix", "custom")
        assert instance.url
        assert instance.name
        assert FEED_CONNECTORS[instance.slug].endswith(connector.__name__)

    @pytest.mark.parametrize("connector", NEW_CONNECTORS)
    def test_connector_is_seeded(self, connector):
        """Without a seed row the connector is unreachable."""
        from pathlib import Path

        seed = Path(__file__).resolve().parents[2] / "scripts" / "seed_feeds.py"
        assert f'"slug": "{connector(api_key=None).slug}"' in seed.read_text(encoding="utf-8")


class TestCISAKEV:
    RAW = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
         "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10",
         "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-502"]},
        {"cveID": "CVE-2021-44228"},          # duplicate
        {"cveID": ""},                        # empty id
        {"vendorProject": "NoCVE"},           # missing id
    ]}

    async def test_parses_dedupes_and_tags(self):
        iocs = await CISAKEVFeed(api_key=None).parse(self.RAW)
        assert len(iocs) == 1
        ioc = iocs[0]
        assert ioc["type"] == "cve"
        assert ioc["value"] == "CVE-2021-44228"
        assert "cisa-kev" in ioc["tags"]
        assert "apache" in ioc["tags"]
        assert "ransomware" in ioc["tags"]
        assert ioc["metadata"]["vulnerability_name"] == "Log4Shell"

    async def test_returns_plain_dicts(self):
        """_normalize_batch does raw.get(...) — pydantic models would raise."""
        iocs = await CISAKEVFeed(api_key=None).parse(self.RAW)
        assert all(isinstance(i, dict) for i in iocs)

    async def test_ransomware_tag_only_when_known(self):
        raw = {"vulnerabilities": [
            {"cveID": "CVE-2020-0001", "knownRansomwareCampaignUse": "Unknown"}
        ]}
        iocs = await CISAKEVFeed(api_key=None).parse(raw)
        assert "ransomware" not in iocs[0]["tags"]

    async def test_empty_catalogue_is_not_an_error(self):
        assert await CISAKEVFeed(api_key=None).parse({}) == []


class TestECrimeLabs:
    async def test_parses_uppercases_and_filters(self):
        raw = "# comment\ncve-2017-0144\nCVE-2017-0144\nnot-a-cve\n\nCVE-2019-0708\n"
        iocs = await ECrimeLabsCVEFeed(api_key=None).parse(raw)
        assert [i["value"] for i in iocs] == ["CVE-2017-0144", "CVE-2019-0708"]
        assert "exploitable" in iocs[0]["tags"]
        assert "metasploit" in iocs[0]["tags"]

    async def test_empty_feed(self):
        assert await ECrimeLabsCVEFeed(api_key=None).parse("") == []


class TestMISPCertFR:
    async def test_parses_lowercases_and_dedupes(self):
        raw = (
            "# hashes\n"
            "D41D8CD98F00B204E9800998ECF8427E,uuid-1\n"
            "d41d8cd98f00b204e9800998ecf8427e,uuid-2\n"
            ",uuid-3\n"
            "badrow\n"
        )
        iocs = await MISPCertFRFeed(api_key=None).parse(raw)
        assert len(iocs) == 1
        assert iocs[0]["value"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert iocs[0]["type"] == "hash"
        assert iocs[0]["metadata"]["misp_event_uuid"] == "uuid-1"
        assert "cert-fr" in iocs[0]["tags"]

    async def test_empty_feed(self):
        assert await MISPCertFRFeed(api_key=None).parse("") == []


class TestIngestionCompatibility:
    """Parsed output must survive validate_ioc/normalize_ioc in the ingest path."""

    async def test_all_new_feeds_survive_normalisation(self):
        batches = [
            await CISAKEVFeed(api_key=None).parse(TestCISAKEV.RAW),
            await ECrimeLabsCVEFeed(api_key=None).parse("CVE-2019-0708\n"),
            await MISPCertFRFeed(api_key=None).parse(
                "d41d8cd98f00b204e9800998ecf8427e,uuid-1\n"
            ),
        ]
        for batch in batches:
            assert _normalize_batch(batch) and len(_normalize_batch(batch)) == len(batch)


class TestApiKeyEnvAllowlist:
    @pytest.mark.parametrize("env", ["SECRET_KEY", "DATABASE_URL", "EMAIL_PASSWORD", "PATH", "HOME"])
    def test_sensitive_env_names_rejected_on_create(self, env):
        """Otherwise the value is forwarded to a third-party API as a key."""
        with pytest.raises(ValidationError):
            FeedCreate(name="x", slug="x", feed_type="api", api_key_env=env)

    @pytest.mark.parametrize("env", ["SECRET_KEY", "DATABASE_URL"])
    def test_sensitive_env_names_rejected_on_update(self, env):
        with pytest.raises(ValidationError):
            FeedUpdate(api_key_env=env)

    @pytest.mark.parametrize("env", [
        "OTX_API_KEY", "ABUSEIPDB_API_KEY", "THREATFOX_API_KEY",
        "MALWAREBAZAAR_API_KEY", "URLHAUS_API_KEY",
    ])
    def test_feed_key_names_accepted(self, env):
        assert FeedCreate(
            name="x", slug="x", feed_type="api", api_key_env=env
        ).api_key_env == env

    @pytest.mark.parametrize("env", [
        "VT_API_KEY", "PHISHTANK_API_KEY",           # connectors deleted
        "SHODAN_API_KEY", "NVD_API_KEY",              # enricher-only
        "YARAIFY_API_KEY", "CVEDETAILS_ACCESS_TOKEN",  # enricher-only
    ])
    def test_unreachable_key_names_rejected(self, env):
        """The allowlist holds only names a live feed connector declares.

        VT and PhishTank lost their connectors; the other four are read from
        ``settings`` by enrichers and can never be reached through a feed row, so
        allowing them widened the H-03 exfiltration surface for nothing. Audited
        down from 11 names to 5 on 2026-07-29.
        """
        with pytest.raises(ValidationError):
            FeedCreate(name="x", slug="x", feed_type="api", api_key_env=env)

    def test_allowlist_matches_the_surviving_connectors(self):
        """Every allowlisted name must be declared by a connector, and vice versa.

        Guards the audit: adding a name here without a connector that reads it
        re-widens the surface, and adding a keyed connector without its name
        breaks that feed's sync with a confusing validation error.
        """
        import importlib
        import pkgutil

        from app import feeds as feeds_pkg
        from app.config import ALLOWED_FEED_API_KEY_ENVS
        from app.feeds.base import BaseFeed

        declared = set()
        for mod in pkgutil.iter_modules(feeds_pkg.__path__):
            module = importlib.import_module(f"app.feeds.{mod.name}")
            for obj in vars(module).values():
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BaseFeed)
                    and obj is not BaseFeed
                    and obj.api_key_env
                ):
                    declared.add(obj.api_key_env)

        assert declared == set(ALLOWED_FEED_API_KEY_ENVS), {
            "declared_but_not_allowed": sorted(declared - set(ALLOWED_FEED_API_KEY_ENVS)),
            "allowed_but_unreachable": sorted(set(ALLOWED_FEED_API_KEY_ENVS) - declared),
        }

    def test_empty_normalises_to_none(self):
        assert FeedCreate(name="x", slug="x", feed_type="api", api_key_env="").api_key_env is None

    def test_slug_format_is_constrained(self):
        with pytest.raises(ValidationError):
            FeedCreate(name="x", slug="Bad Slug!", feed_type="api")


class TestSchedulerAllowlistEnforcement:
    async def test_disallowed_api_key_env_is_not_dereferenced(self, monkeypatch):
        """Defence in depth for feed rows created before the schema validator."""
        from app.services import feed_scheduler

        monkeypatch.setenv("SECRET_KEY", "super-secret-signing-key")
        captured = {}

        class _FakeFeed:
            id = "feed-1"
            slug = "urlhaus"
            api_key_env = "SECRET_KEY"

        class _Session:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                return False
            async def execute(self, *a, **k):
                class R:
                    def scalar_one_or_none(self_inner):
                        return _FakeFeed()
                return R()
            async def commit(self):
                pass

        monkeypatch.setattr(feed_scheduler, "AsyncSessionLocal", lambda: _Session())

        class _Connector:
            def __init__(self, api_key=None):
                captured["api_key"] = api_key
            async def run(self):
                raise RuntimeError("stop here — we only care about key resolution")

        import sys
        import types

        module = types.ModuleType("tests._fake_connector")
        module.FakeConnector = _Connector
        sys.modules["tests._fake_connector"] = module

        await feed_scheduler._run_feed_sync_inner(
            "feed-1", "urlhaus", "tests._fake_connector.FakeConnector"
        )
        assert captured["api_key"] is None, "SECRET_KEY must never reach a connector"


# Two rows copied verbatim from https://bazaar.abuse.ch/export/csv/recent/ on
# 2026-07-30, hashes truncated-then-padded so they are structurally valid without
# reproducing real sample digests. Note the shape being pinned:
#   - the column header is INSIDE a "#" comment, so DictReader cannot find it;
#   - rows carry 14 fields, while the comment header names only 12;
#   - "n/a" is the empty marker, not "".
_MB_PUBLIC_CSV = (
    "# ###############################################################\n"
    "#  MalwareBazaar recent malware samples (CSV)                   #\n"
    "#  Last updated: 2026-07-30 11:07:12 UTC                        #\n"
    "# ###############################################################\n"
    "# \n"
    '#  "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter",'
    '"file_name","file_type_guess","mime_type","signature","clamav","vtpercent",'
    '"imphash"\n'
    "#  Number of entries: 2\n"
    "# \n"
    '"2026-07-30 11:07:12","' + "a" * 64 + '","' + "b" * 32 + '","' + "c" * 40 + '",'
    '"Bitsight","file","exe","application/x-dosexec","n/a","n/a","n/a",'
    '"' + "d" * 32 + '","196608:f15g1dVcBpV4rUcug","T1E5D6236771551A59D2"\n'
    '"2026-07-29 08:15:00","' + "e" * 64 + '","' + "f" * 32 + '","' + "1" * 40 + '",'
    '"anonymous","invoice.doc","doc","application/msword","WannaCry",'
    '"Win.Trojan.Agent","62","n/a","n/a","n/a"\n'
)


class TestMalwareBazaarPublicExport:
    """The keyless CSV export is what lets this feed ingest without a credential.

    abuse.ch's JSON APIs return 401 unauthenticated (verified 2026-07-30), but
    bazaar.abuse.ch/export/csv/recent/ returns 200. The connector reads the public
    export unconditionally and treats an Auth-Key as additive.
    """

    def _parse(self):
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        return MalwareBazaarFeed(api_key=None)._parse_public_recent_csv(
            _MB_PUBLIC_CSV, set()
        )

    def test_commented_header_does_not_eat_the_first_data_row(self):
        """The bug this parser exists to avoid.

        `_split_csv_header_and_data` (used for the *keyed* export) takes the first
        non-# line as the header. Here that line is a data row, so the newest sample
        would be silently dropped and every field would be keyed by a hash value.
        Two samples in, six IOCs out — three hash types each.
        """
        iocs = self._parse()
        assert len(iocs) == 6, [i["value"][:12] for i in iocs]
        assert {i["type"] for i in iocs} == {"hash"}
        assert "a" * 64 in {i["value"] for i in iocs}, "newest row was dropped"

    def test_all_three_hash_types_are_emitted(self):
        iocs = self._parse()
        kinds = [i["metadata"]["hash_type"] for i in iocs]
        assert sorted(kinds) == ["md5", "md5", "sha1", "sha1", "sha256", "sha256"]

    def test_na_markers_do_not_become_tags_or_metadata(self):
        """abuse.ch writes the string 'n/a' for absent values, not an empty field."""
        iocs = self._parse()
        for ioc in iocs:
            assert not any("n/a" in tag for tag in ioc["tags"]), ioc["tags"]
            for key, value in ioc["metadata"].items():
                assert value != "n/a", (key, value)

    def test_signature_and_clamav_become_tags(self):
        iocs = self._parse()
        wannacry = [i for i in iocs if i["metadata"]["signature"] == "WannaCry"]
        assert wannacry, "the signed row produced no IOCs"
        tags = wannacry[0]["tags"]
        assert "malwarebazaar" in tags
        assert "wannacry" in tags
        assert "win.trojan.agent" in tags, tags

    def test_field_alignment_survives_the_two_undocumented_columns(self):
        """14 fields per row against 12 documented names.

        If the extra ssdeep/tlsh columns were not named, DictReader would fold them
        into a `None` key and — worse for a positional reader — any future edit that
        trusted the documented count would shift every field after `imphash`.
        """
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        assert len(MalwareBazaarFeed._PUBLIC_CSV_FIELDNAMES) == 14
        iocs = self._parse()
        first = next(i for i in iocs if i["value"] == "a" * 64)
        assert first["metadata"]["mime_type"] == "application/x-dosexec"
        assert first["metadata"]["imphash"] == "d" * 32
        assert first["metadata"]["reporter"] == "Bitsight"

    def test_timestamps_are_parsed_not_dropped(self):
        iocs = self._parse()
        assert all(i["first_seen"] is not None for i in iocs)
        assert {str(i["first_seen"].tzinfo) for i in iocs} == {"UTC"}

    def test_parse_returns_plain_dicts(self):
        """`feed_ingestion._normalize_batch` calls raw.get(); models raise."""
        iocs = self._parse()
        assert all(isinstance(i, dict) for i in iocs)
        assert all(i.get("type") == "hash" for i in iocs)

    def test_empty_or_comment_only_input_is_safe(self):
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        feed = MalwareBazaarFeed(api_key=None)
        assert feed._parse_public_recent_csv("", set()) == []
        assert feed._parse_public_recent_csv("# only a comment\n", set()) == []

    def test_dedup_set_is_honoured_across_sources(self):
        """The keyed export must not re-emit what the public one already produced."""
        seen = {"a" * 64}
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        iocs = MalwareBazaarFeed(api_key=None)._parse_public_recent_csv(
            _MB_PUBLIC_CSV, seen
        )
        assert "a" * 64 not in {i["value"] for i in iocs}
        assert len(iocs) == 5

    def test_the_GOVERNING_interval_is_at_most_half_the_measured_window(self):
        """Assert against the interval that actually governs, not the connector default.

        `default_sync_frequency` is a floor: the live path is `sync-all` driven by
        external cron, which in smart mode syncs only when
        `(now - last_sync_at) >= sync_frequency`. The effective interval is
        therefore the *coarser* of the cron cadence and that value — 6 hours with
        cron at 4x/day, not the 1 hour the attribute suggests.

        The earlier version of this test compared the 1-hour floor against the
        window and reported a 24x margin. The real margin is 8x.
        """
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        window_seconds = MalwareBazaarFeed._PUBLIC_WINDOW_HOURS * 3600
        governing = MalwareBazaarFeed._GOVERNING_SYNC_INTERVAL_SECONDS
        assert governing <= window_seconds / 2, (
            f"governing interval {governing}s exceeds half the measured "
            f"{MalwareBazaarFeed._PUBLIC_WINDOW_HOURS}h window"
        )
        margin = window_seconds / governing
        assert margin >= 4, f"margin is only {margin:.1f}x"

    def test_sync_frequency_stays_strictly_below_the_cron_interval(self):
        """Equal values skip every other firing and halve the real cadence.

        `last_sync_at` is written when ingestion *finishes*, so if
        `sync_frequency == cron_interval` the elapsed time at the next firing is
        short by the sync's own duration, the feed is judged not overdue, and it is
        skipped. Spec 2's 720-minute figure had exactly that effect.
        """
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        assert (
            MalwareBazaarFeed.default_sync_frequency
            < MalwareBazaarFeed._GOVERNING_SYNC_INTERVAL_SECONDS
        )

    def test_feed_type_reflects_how_ingestion_actually_works(self):
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        assert MalwareBazaarFeed.feed_type == "csv"

    def test_the_connector_opts_into_window_continuity_checking(self):
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        assert MalwareBazaarFeed.rolling_window is True

    def test_parsing_records_the_window_it_observed(self):
        """The watermark input, taken from the file rather than assumed."""
        from datetime import datetime, timezone

        from app.feeds.malwarebazaar import MalwareBazaarFeed

        feed = MalwareBazaarFeed(api_key=None)
        assert feed.observed_window is None
        feed._parse_public_recent_csv(_MB_PUBLIC_CSV, set())

        assert feed.observed_window is not None
        lo, hi = feed.observed_window
        assert lo == datetime(2026, 7, 29, 8, 15, 0, tzinfo=timezone.utc)
        assert hi == datetime(2026, 7, 30, 11, 7, 12, tzinfo=timezone.utc)

    def test_an_empty_file_records_no_window_rather_than_a_false_one(self):
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        feed = MalwareBazaarFeed(api_key=None)
        feed._parse_public_recent_csv("# nothing but a comment\n", set())
        assert feed.observed_window is None


class TestFeedTypeIsDescriptiveOnly:
    """`feed_type` must not drive dispatch, or a stale value is a live bug.

    Audited 2026-07-30: the only consumers are `api/feeds.py:48` (copying the
    operator's submitted value onto a new row) and the schema field description.
    Connector selection is by **slug** through `FEED_CONNECTORS`, and parsing is
    chosen inside each connector's own `parse()`. So `feed_type` is metadata for
    humans and the UI. This test exists so that stops being true loudly.
    """

    def test_connector_resolution_ignores_feed_type(self):
        from app.services.feed_scheduler import FEED_CONNECTORS

        assert FEED_CONNECTORS["malwarebazaar"].endswith("MalwareBazaarFeed")

    def test_no_dispatch_on_feed_type_in_the_ingest_or_sync_paths(self):
        """Grep-as-a-test: catches a future `if feed.feed_type == ...` branch."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1] / "app"
        offenders = []
        for path in root.rglob("*.py"):
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                # A comparison or branch on feed_type would be dispatch.
                if "feed_type" in stripped and any(
                    op in stripped for op in ("==", "!=", " in ", "elif", "match ")
                ):
                    offenders.append(f"{path.relative_to(root)}:{lineno}: {stripped}")
        assert not offenders, (
            "feed_type is documented as descriptive-only but is now branched on:\n"
            + "\n".join(offenders)
        )


class TestRollingWindowContinuity:
    """Silent data loss on a rolling-window export becomes a visible field.

    Each individual sync of a rolling export looks healthy — 200, a full file,
    hundreds of new IOCs — even when the interval exceeded the window and records
    appeared and aged out unseen in between. The only detectable signature is a
    discontinuity between the previous file's latest record and the next file's
    earliest.
    """

    def _feed_row(self, watermark=None):
        class _Feed:
            slug = "malwarebazaar"
            last_ingest_watermark = watermark
            last_ingest_gap = None

        return _Feed()

    def _connector(self, lo, hi, rolling=True):
        class _Conn:
            rolling_window = rolling
            observed_window = (lo, hi) if lo else None

        return _Conn()

    def test_a_gap_is_detected_and_described(self):
        from datetime import datetime, timezone

        from app.services.feed_scheduler import _check_window_continuity

        feed = self._feed_row(watermark=datetime(2026, 7, 20, 0, 0, 0))
        conn = self._connector(
            datetime(2026, 7, 25, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 27, 0, 0, 0, tzinfo=timezone.utc),
        )
        detail = _check_window_continuity(feed, conn)

        assert detail is not None, "a 5-day discontinuity was not reported"
        assert "5 days" in detail, detail
        assert feed.last_ingest_gap == detail
        # Watermark still advances so the next run compares against reality.
        assert feed.last_ingest_watermark == datetime(2026, 7, 27, 0, 0, 0)

    def test_contiguous_windows_report_no_gap(self):
        from datetime import datetime, timezone

        from app.services.feed_scheduler import _check_window_continuity

        feed = self._feed_row(watermark=datetime(2026, 7, 26, 0, 0, 0))
        conn = self._connector(
            datetime(2026, 7, 25, 0, 0, 0, tzinfo=timezone.utc),  # overlaps — good
            datetime(2026, 7, 27, 0, 0, 0, tzinfo=timezone.utc),
        )
        assert _check_window_continuity(feed, conn) is None
        assert feed.last_ingest_gap is None
        assert feed.last_ingest_watermark == datetime(2026, 7, 27, 0, 0, 0)

    def test_the_first_ever_sync_is_not_a_gap(self):
        """NULL watermark means no evidence either way, not data loss."""
        from datetime import datetime, timezone

        from app.services.feed_scheduler import _check_window_continuity

        feed = self._feed_row(watermark=None)
        conn = self._connector(
            datetime(2026, 7, 25, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 27, 0, 0, 0, tzinfo=timezone.utc),
        )
        assert _check_window_continuity(feed, conn) is None
        assert feed.last_ingest_watermark == datetime(2026, 7, 27, 0, 0, 0)

    def test_the_watermark_never_moves_backwards(self):
        """A short or partial file must not lower it and fake a gap next run."""
        from datetime import datetime, timezone

        from app.services.feed_scheduler import _check_window_continuity

        feed = self._feed_row(watermark=datetime(2026, 7, 30, 0, 0, 0))
        conn = self._connector(
            datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 22, 0, 0, 0, tzinfo=timezone.utc),
        )
        _check_window_continuity(feed, conn)
        assert feed.last_ingest_watermark == datetime(2026, 7, 30, 0, 0, 0)

    def test_full_catalogue_feeds_are_untouched(self):
        """Opt-in only — a timestamp-free source would else report a gap every sync."""
        from datetime import datetime, timezone

        from app.services.feed_scheduler import _check_window_continuity

        feed = self._feed_row(watermark=datetime(2026, 7, 20, 0, 0, 0))
        conn = self._connector(
            datetime(2026, 7, 25, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 27, 0, 0, 0, tzinfo=timezone.utc),
            rolling=False,
        )
        assert _check_window_continuity(feed, conn) is None
        assert feed.last_ingest_watermark == datetime(2026, 7, 20, 0, 0, 0)

    def test_a_connector_that_recorded_no_window_is_ignored(self):
        from datetime import datetime

        from app.services.feed_scheduler import _check_window_continuity

        feed = self._feed_row(watermark=datetime(2026, 7, 20, 0, 0, 0))
        assert _check_window_continuity(feed, self._connector(None, None)) is None

    def test_naive_and_aware_timestamps_are_compared_safely(self):
        """The watermark is naive UTC; connector timestamps are aware.

        Mixing them in a comparison raises TypeError in Python, which would abort
        a sync that had already succeeded. Pinned because the project's datetime
        convention makes this collision easy to reintroduce.
        """
        from datetime import datetime, timezone

        from app.services.feed_scheduler import _check_window_continuity

        feed = self._feed_row(watermark=datetime(2026, 7, 20, 0, 0, 0))  # naive
        conn = self._connector(
            datetime(2026, 7, 25, 0, 0, 0, tzinfo=timezone.utc),        # aware
            datetime(2026, 7, 27, 0, 0, 0, tzinfo=timezone.utc),
        )
        detail = _check_window_continuity(feed, conn)
        assert detail is not None
        assert feed.last_ingest_watermark.tzinfo is None

    def test_the_check_never_raises(self):
        """A monitoring aid must not be able to fail an ingest that succeeded."""
        from app.services.feed_scheduler import _check_window_continuity

        class _Hostile:
            rolling_window = True

            @property
            def observed_window(self):
                return ("not", "datetimes")

        feed = self._feed_row(watermark=None)
        assert _check_window_continuity(feed, _Hostile()) is None

    def test_a_gap_is_cleared_once_contiguity_returns(self):
        from datetime import datetime, timezone

        from app.services.feed_scheduler import _check_window_continuity

        feed = self._feed_row(watermark=datetime(2026, 7, 20, 0, 0, 0))
        feed.last_ingest_gap = "a gap from a previous run"
        conn = self._connector(
            datetime(2026, 7, 19, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 21, 0, 0, 0, tzinfo=timezone.utc),
        )
        assert _check_window_continuity(feed, conn) is None
        assert feed.last_ingest_gap is None, "a stale gap must not persist"

    def test_the_feed_no_longer_requires_a_key(self):
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        assert MalwareBazaarFeed.requires_api_key is False
        assert MalwareBazaarFeed.url == "https://bazaar.abuse.ch/export/csv/recent/"

    def test_the_enricher_is_still_gated_the_split_is_deliberate(self):
        """A bulk export cannot answer a single-hash lookup.

        Feed ingestion is keyless; hash *enrichment* is not, because no keyless
        endpoint serves arbitrary hash lookups. If this ever fails, check that the
        two were not collapsed together.
        """
        from app.config import settings
        from app.enrichers import get_enricher, reset_registry

        original = settings.MALWAREBAZAAR_API_KEY
        try:
            settings.MALWAREBAZAAR_API_KEY = None
            reset_registry()
            assert get_enricher("malwarebazaar") is None
        finally:
            settings.MALWAREBAZAAR_API_KEY = original
            reset_registry()


class TestRollingWindowCoverage:
    """Every connector reading a rolling-window export must opt into the check.

    Added after MalwareBazaar: URLhaus's csv_recent and ThreatFox's CSV exports are
    the same class of source, and leaving them unmonitored left the same silent loss
    undetected. Their windows were also only *assumed* until measured — one of the
    assumptions was wrong by an order of magnitude.
    """

    def test_the_three_rolling_window_feeds_opt_in(self):
        from app.feeds.malwarebazaar import MalwareBazaarFeed
        from app.feeds.threatfox import ThreatFoxFeed
        from app.feeds.urlhaus import URLhausFeed

        for connector in (MalwareBazaarFeed, ThreatFoxFeed, URLhausFeed):
            assert connector.rolling_window is True, connector.__name__

    def test_full_catalogue_feeds_do_not_opt_in(self):
        """Opt-in must stay opt-in — a timestamp-free source reports a false gap."""
        from app.feeds.blocklist_de import BlocklistDeFeed
        from app.feeds.cisa_kev import CISAKEVFeed
        from app.feeds.ecrimelabs import ECrimeLabsCVEFeed
        from app.feeds.emergingthreats import EmergingThreatsFeed
        from app.feeds.misp_cert_fr import MISPCertFRFeed

        for connector in (CISAKEVFeed, ECrimeLabsCVEFeed, MISPCertFRFeed,
                          BlocklistDeFeed, EmergingThreatsFeed):
            assert connector.rolling_window is False, connector.__name__

    def test_measured_windows_leave_room_for_the_governing_interval(self):
        """Each measured window must be at least twice the interval that governs.

        The figures are measured from the live files, not taken from docs — the
        docs would have told you URLhaus csv_recent was 48 hours when it is 733.
        """
        from app.feeds.malwarebazaar import MalwareBazaarFeed
        from app.feeds.threatfox import ThreatFoxFeed
        from app.feeds.urlhaus import URLhausFeed

        governing_hours = (
            MalwareBazaarFeed._GOVERNING_SYNC_INTERVAL_SECONDS / 3600
        )
        measured = {
            "malwarebazaar": MalwareBazaarFeed._PUBLIC_WINDOW_HOURS,
            "urlhaus": URLhausFeed._MEASURED_WINDOW_HOURS,
            "threatfox": ThreatFoxFeed._MEASURED_WINDOW_HOURS,
        }
        for name, hours in measured.items():
            assert hours >= governing_hours * 2, (
                f"{name}: measured window {hours}h is under twice the "
                f"{governing_hours}h governing interval"
            )

    def test_malwarebazaar_is_the_tightest_margin(self):
        """Documents where the risk actually sits, so it is not re-derived.

        MalwareBazaar 8x, URLhaus ~122x, ThreatFox ~706x. If a future change makes
        another feed the tightest, that is worth noticing deliberately.
        """
        from app.feeds.malwarebazaar import MalwareBazaarFeed
        from app.feeds.threatfox import ThreatFoxFeed
        from app.feeds.urlhaus import URLhausFeed

        assert MalwareBazaarFeed._PUBLIC_WINDOW_HOURS < URLhausFeed._MEASURED_WINDOW_HOURS
        assert URLhausFeed._MEASURED_WINDOW_HOURS < ThreatFoxFeed._MEASURED_WINDOW_HOURS

    def test_urlhaus_records_the_window_only_from_csv_recent(self):
        """online_csv is a status selection, not a time window.

        A URL that has been online for a year would drag the minimum back a year and
        mask every real gap. Verified live: parsing online_csv alone leaves
        observed_window as None.
        """
        import asyncio

        from app.feeds.urlhaus import URLhausFeed

        assert URLhausFeed._WINDOW_SOURCE == "recent_csv"

        row = (
            '"1","2026-07-30 12:00:00","http://evil.example/a","online",'
            '"2026-07-30 12:00:00","malware_download","None",'
            '"https://urlhaus.abuse.ch/url/1/","reporter"\n'
        )
        feed = URLhausFeed(api_key=None)
        asyncio.run(feed.parse({"recent_csv": "", "online_csv": row}))
        assert feed.observed_window is None, "online_csv must not set the window"

        feed2 = URLhausFeed(api_key=None)
        asyncio.run(feed2.parse({"recent_csv": row, "online_csv": ""}))
        assert feed2.observed_window is not None, "recent_csv must set the window"

    def test_threatfox_excludes_expired_records_from_the_window(self):
        """A record dropped for age was not lost to a sync gap.

        Counting expired rows would push the observed minimum back to the 180-day
        cutoff and mask genuine discontinuities behind it.
        """
        from datetime import datetime, timedelta, timezone

        from app.feeds.threatfox import ThreatFoxFeed

        fresh = datetime.now(timezone.utc) - timedelta(days=1)
        expired = datetime.now(timezone.utc) - timedelta(days=400)
        fmt = "%Y-%m-%d %H:%M:%S"
        csv_text = (
            f'"{expired.strftime(fmt)}","1","aaaa.example","domain","malware_download",'
            f'"Emotet","","","","","reporter",""\n'
            f'"{fresh.strftime(fmt)}","2","bbbb.example","domain","malware_download",'
            f'"Emotet","","","","","reporter",""\n'
        )
        feed = ThreatFoxFeed(api_key=None)
        stamps = []
        feed._parse_export_csv(csv_text, set(), window_timestamps=stamps)

        assert stamps, "no timestamps recorded"
        assert all(
            (datetime.now(timezone.utc) - s).days < 180 for s in stamps
        ), "an expired record leaked into the observed window"


class TestDeclarationTaxonomy:
    """`rolling_window` and `full_list_kind` must not both be set.

    Both set means the gate silently picks whichever branch is ordered first — the
    exact failure just fixed, where the `no-source-timestamp` fallback preceded the
    kind test and quietly negated the whole cumulative branch while its tests passed.

    Scheduled for collapse into one taxonomy in Section 1, which is touching the same
    declaration surface for `assessed`. Until then this holds the line.
    """

    @staticmethod
    def _connectors():
        import importlib
        import inspect
        import pkgutil

        from app import feeds as feeds_pkg
        from app.feeds.base import BaseFeed

        out = {}
        for mod in pkgutil.iter_modules(feeds_pkg.__path__):
            module = importlib.import_module("app.feeds." + mod.name)
            for obj in vars(module).values():
                if (isinstance(obj, type) and issubclass(obj, BaseFeed)
                        and obj is not BaseFeed):
                    src = inspect.getsource(obj)
                    out[obj.__name__] = (
                        obj.rolling_window,
                        obj.full_list_kind,
                        ("first_seen=" in src or "last_seen=" in src),
                    )
        return out

    def test_no_connector_declares_both(self):
        """Mutual exclusion. They answer different questions and cannot both apply.

        `rolling_window` needs per-record timestamps — it records min/max of them to
        detect gaps. `full_list_kind` exists precisely because a feed has none. A
        connector claiming both is describing something incoherent, and the gate would
        resolve it by branch order rather than by meaning.
        """
        offenders = {
            name: (rw, kind)
            for name, (rw, kind, _ts) in self._connectors().items()
            if rw and kind is not None
        }
        assert not offenders, (
            "these connectors declare both rolling_window and full_list_kind, which "
            "cannot both be true — the gate would pick by branch order: "
            + repr(offenders)
        )

    def test_at_most_one_declaration_never_exactly_one(self):
        """AT most one, not exactly one — and that distinction is deliberate.

        Three connectors declare neither and are right to: AbuseIPDB, Feodo Tracker
        and OTX all supply per-record timestamps, so the re-read gate works through
        the timestamp path and needs no declaration. Asserting "exactly one" would
        force a false declaration on them.
        """
        conns = self._connectors()
        neither = sorted(
            name for name, (rw, kind, _ts) in conns.items()
            if not rw and kind is None
        )
        # Every connector declaring neither MUST supply timestamps, or the gate has
        # nothing to work with and the counter inflates.
        for name in neither:
            _rw, _kind, supplies_ts = conns[name]
            assert supplies_ts, (
                name + " declares neither rolling_window nor full_list_kind AND "
                "supplies no per-record timestamps — its sighting counter will "
                "inflate on every sync"
            )

    def test_the_current_declaration_state_is_pinned(self):
        """Records today's assignment, so a change is deliberate rather than drift.

        Also documents an open question for Section 1's collapse: AbuseIPDB's
        blacklist ("most reported in the last N days") and Feodo Tracker's
        recommended list (currently-active C2s) are arguably rolling windows too, and
        would benefit from gap detection. They are left undeclared for now because
        adding it changes what is monitored, not what is scored.
        """
        expected = {
            # rolling windows, all timestamped
            "URLhausFeed": (True, None),
            "ThreatFoxFeed": (True, None),
            "MalwareBazaarFeed": (True, None),
            # current-state full lists, no timestamps
            "BlocklistDeFeed": (False, "current-state"),
            "EmergingThreatsFeed": (False, "current-state"),
            # cumulative catalogues, no timestamps
            "CISAKEVFeed": (False, "cumulative"),
            "ECrimeLabsCVEFeed": (False, "cumulative"),
            "MISPCertFRFeed": (False, "cumulative"),
            # timestamped, undeclared — see the docstring
            "AbuseIPDBFeed": (False, None),
            "FeodoTrackerFeed": (False, None),
            "OTXAlienVaultFeed": (False, None),
        }
        actual = {n: (rw, kind) for n, (rw, kind, _) in self._connectors().items()}
        assert actual == expected, (
            "connector declarations changed. If deliberate, update this table and "
            "consider whether the scoring consequence was intended.\n  expected: "
            + repr(sorted(expected.items())) + "\n  actual:   "
            + repr(sorted(actual.items()))
        )
