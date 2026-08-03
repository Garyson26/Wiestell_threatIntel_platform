"""Enricher registry, dispatch, TTLs and extractor robustness."""

import pytest

from app.config import settings
from app.enrichers import applicable_sources, get_enricher, get_registry, reset_registry
from app.enrichers.base import BaseEnricher
from app.enrichers.cvedetails_enricher import CVEDetailsEnricher
from app.enrichers.nvd_enricher import NVDEnricher
from app.enrichers.yaraify_enricher import YARAifyEnricher
from app.services.enrichment_engine import _get_applicable_sources, _get_ttl


@pytest.fixture(autouse=True)
def _clean_registry():
    reset_registry()
    yield
    reset_registry()


@pytest.fixture
def geoip_db(monkeypatch, tmp_path):
    """A present-and-readable .mmdb, so GeoIP registers.

    The real file is not committed — it is fetched at build time — so
    ``GEOIP_DB_PATH`` points at a path that does not exist during a test run. Since
    2026-07-31 GeoIP is gated on that file, so anything asserting the per-type source
    table has to state which side of the gate it is testing. The contents are never
    read: the gate is an existence check and no test performs a lookup.
    """
    db = tmp_path / "GeoLite2-City.mmdb"
    db.write_bytes(b"not a real mmdb")
    monkeypatch.setattr(settings, "GEOIP_DB_PATH", str(db))
    reset_registry()
    return db


@pytest.fixture
def no_keys(monkeypatch, geoip_db):
    for name in ("NVD_API_KEY", "CVEDETAILS_ACCESS_TOKEN", "YARAIFY_API_KEY",
                 "MALWAREBAZAAR_API_KEY"):
        monkeypatch.setattr(settings, name, None)
    reset_registry()


@pytest.fixture
def all_keys(monkeypatch, geoip_db):
    monkeypatch.setattr(settings, "NVD_API_KEY", "nvd-key")
    monkeypatch.setattr(settings, "CVEDETAILS_ACCESS_TOKEN", "cvedetails-token")
    monkeypatch.setattr(settings, "YARAIFY_API_KEY", "yaraify-key")
    monkeypatch.setattr(settings, "MALWAREBAZAAR_API_KEY", "mb-key")
    reset_registry()


@pytest.fixture
def no_geoip_db(monkeypatch):
    """The MaxMind file absent — the state a deploy without MAXMIND_* lands in."""
    monkeypatch.setattr(settings, "GEOIP_DB_PATH", "/nonexistent/GeoLite2-City.mmdb")
    reset_registry()


class TestRegistryGating:
    def test_credential_free_enrichers_are_always_registered(self, no_keys):
        """These degrade gracefully rather than disappearing.

        `malwarebazaar` was in this set until 2026-07-30. abuse.ch now returns
        HTTP 401 for unauthenticated JSON API calls, and the enricher's
        raise_for_status() turned that into an {"error": "...401..."} row against
        every hash IOC — the exact anti-pattern gating exists to prevent. It moved
        to the gated set below.
        """
        registered = set(get_registry())
        assert {"geoip", "whois", "dns", "reputation", "shodan", "nvd"} <= registered

    def test_keyless_nvd_is_always_registered(self, no_keys):
        assert "nvd" in applicable_sources("cve")

    def test_geoip_is_gated_on_its_database_file(self, no_geoip_db):
        """The .mmdb is GeoIP's credential, and it is frequently absent.

        Without the file every lookup raised inside the enricher and it stored
        {"error_city": "GeoIP city database not available"} against every IP IOC —
        the same anti-pattern that moved malwarebazaar into the gated set. The file is
        not committed; it is fetched by a build step that fails open
        (`download_geolite2.py || echo "...continuing"`) and needs MAXMIND_ACCOUNT_ID
        and MAXMIND_LICENSE_KEY.
        """
        assert "geoip" not in get_registry()
        assert "geoip" not in applicable_sources("ip")

    def test_geoip_registers_when_the_database_is_present(self, geoip_db):
        assert "geoip" in get_registry()
        assert "geoip" in applicable_sources("ip")

    def test_gating_geoip_does_not_disturb_the_remaining_ip_order(self, no_geoip_db):
        """Registration order is the attempt order, so the gate must only remove.

        Dropping geoip must leave the rest of the IP chain in the same sequence — the
        contract TestEngineDispatch pins with the database present.
        """
        assert applicable_sources("ip") == ["whois", "dns", "reputation", "shodan"]

    def test_an_absent_database_does_not_silently_pass(self, no_geoip_db, capsys):
        """It has to be visible somewhere, or a keyless deploy loses geo unnoticed.

        Logging is the interim surface; exposing it in /health is recorded as Phase 6
        work in PROJECT_SUMMARY.md §8 item 14.

        Asserted against captured stdout rather than ``caplog``: structlog renders
        through its own processor chain to stdout and does not route these records
        through stdlib logging, so ``caplog.records`` is empty even when the warning is
        emitted. A caplog-based assertion here fails silently in the other direction —
        it would pass vacuously if the warning were later removed.
        """
        get_registry()
        out = capsys.readouterr()
        assert "geoip_database_missing" in (out.out + out.err), (
            "the missing GeoIP database produced no log record"
        )

    def test_gated_enrichers_absent_without_credentials(self, no_keys):
        assert get_enricher("cvedetails") is None
        assert get_enricher("yaraify") is None
        assert get_enricher("malwarebazaar") is None
        assert "yaraify" not in applicable_sources("hash")
        assert "malwarebazaar" not in applicable_sources("hash")
        assert "cvedetails" not in applicable_sources("cve")

    def test_malwarebazaar_needs_the_abusech_key(self, monkeypatch):
        """Gated because abuse.ch's query API is no longer open.

        Verified 2026-07-30: POST https://mb-api.abuse.ch/api/v1/ without an
        Auth-Key header returns 401 {"error": "Unauthorized"}. There is no
        unauthenticated per-hash lookup — the bulk CSV export at
        bazaar.abuse.ch/export/csv/recent/ is still open but cannot answer a
        single-hash query, which is what enrichment needs.
        """
        monkeypatch.setattr(settings, "MALWAREBAZAAR_API_KEY", None)
        reset_registry()
        assert get_enricher("malwarebazaar") is None

        monkeypatch.setattr(settings, "MALWAREBAZAAR_API_KEY", "shared-abusech-key")
        reset_registry()
        assert get_enricher("malwarebazaar") is not None
        assert "malwarebazaar" in applicable_sources("hash")

    def test_malwarebazaar_keeps_its_registration_position(self, all_keys):
        """Gating must not reorder the registry — order is the attempt order."""
        hash_sources = applicable_sources("hash")
        assert hash_sources.index("reputation") < hash_sources.index("malwarebazaar")
        assert hash_sources.index("malwarebazaar") < hash_sources.index("yaraify")

    def test_all_registered_when_configured(self, all_keys):
        assert {"nvd", "cvedetails"} <= set(applicable_sources("cve"))
        assert "yaraify" in applicable_sources("hash")

    def test_yaraify_falls_back_to_the_abusech_key(self, monkeypatch):
        monkeypatch.setattr(settings, "YARAIFY_API_KEY", None)
        monkeypatch.setattr(settings, "MALWAREBAZAAR_API_KEY", "shared-abusech-key")
        reset_registry()
        assert get_enricher("yaraify").api_key == "shared-abusech-key"

    def test_registry_names_match_enricher_names(self, all_keys):
        for key, enricher in get_registry().items():
            assert key == enricher.name

    def test_every_registered_enricher_honours_the_base_contract(self, all_keys):
        for enricher in get_registry().values():
            assert isinstance(enricher, BaseEnricher)
            assert enricher.cache_ttl > 0
            assert isinstance(enricher.supports("cve"), bool)


class TestSupports:
    def test_cve_enrichers_only_accept_cve(self):
        for enricher in (NVDEnricher(), CVEDetailsEnricher("token")):
            assert enricher.supports("cve") is True
            for other in ("ip", "domain", "hash", "url", "email"):
                assert enricher.supports(other) is False

    def test_yaraify_only_accepts_hash(self):
        enricher = YARAifyEnricher("key")
        assert enricher.supports("hash") is True
        assert enricher.supports("cve") is False


class TestEngineDispatch:
    """The externally visible contract: which sources run for which IOC type.

    This table is the regression guard for the registry consolidation — it must
    keep matching the behaviour that shipped before enrichers moved out of
    ``enrichment_engine`` into ``app.enrichers``.
    """

    EXPECTED = {
        "ip":     ["geoip", "whois", "dns", "reputation", "shodan"],
        "domain": ["whois", "dns", "reputation"],
        "url":    ["whois", "dns", "reputation"],
        # malwarebazaar and yaraify are both abuse.ch-key-gated as of
        # 2026-07-30, so neither appears in the no_keys baseline.
        "hash":   ["reputation"],
        "email":  ["whois", "reputation"],
        "cve":    ["reputation"],
    }

    @pytest.mark.parametrize("ioc_type", sorted(EXPECTED))
    def test_core_sources_per_type(self, no_keys, ioc_type):
        sources = _get_applicable_sources(ioc_type)
        assert set(self.EXPECTED[ioc_type]) <= set(sources), (
            f"{ioc_type}: expected {self.EXPECTED[ioc_type]}, got {sources}"
        )

    def test_ip_source_order_is_preserved(self, no_keys):
        """Registry insertion order determines attempt order."""
        assert _get_applicable_sources("ip") == [
            "geoip", "whois", "dns", "reputation", "shodan"
        ]

    def test_gated_enrichers_extend_the_core_set(self, all_keys):
        assert {"reputation", "nvd", "cvedetails"} <= set(_get_applicable_sources("cve"))
        assert {"reputation", "malwarebazaar", "yaraify"} <= set(_get_applicable_sources("hash"))

    def test_no_duplicate_sources(self, all_keys):
        for ioc_type in ("ip", "domain", "url", "hash", "email", "cve"):
            sources = _get_applicable_sources(ioc_type)
            assert len(sources) == len(set(sources))

    def test_unknown_ioc_type_falls_back_to_reputation(self, no_keys):
        assert _get_applicable_sources("something-new") == ["reputation"]

    def test_broken_registry_degrades_instead_of_raising(self, monkeypatch):
        """A registry failure must yield "no enrichment", never a 500.

        Note the trade-off from consolidation: with a single source of truth
        there is no hardcoded built-in list left to fall back on, so a
        registry-wide failure disables enrichment entirely rather than partially.
        """
        import app.services.enrichment_engine as engine

        def _explode(_ioc_type):
            raise RuntimeError("registry unavailable")

        monkeypatch.setattr("app.enrichers.applicable_sources", _explode)
        assert engine._get_applicable_sources("cve") == []


class TestTTLs:
    def test_registry_enrichers_supply_their_own_ttl(self, all_keys):
        assert _get_ttl("nvd") == NVDEnricher.cache_ttl
        assert _get_ttl("yaraify") == YARAifyEnricher.cache_ttl
        assert _get_ttl("cvedetails") == CVEDetailsEnricher.cache_ttl

    def test_builtin_ttls_come_from_settings(self):
        assert _get_ttl("whois") == settings.CACHE_TTL_WHOIS
        assert _get_ttl("dns") == settings.CACHE_TTL_DNS

    def test_unknown_source_falls_back(self):
        assert _get_ttl("no-such-source") == 3600


class TestBlockingCallsStayOffTheEventLoop:
    async def test_whois_runs_in_an_executor(self, monkeypatch):
        """`whois.whois` is synchronous and network-bound.

        Calling it inline would stall the whole event loop for the duration of
        the query. The enricher must hand it to a thread pool.
        """
        import threading

        from app.enrichers.whois_enricher import WhoisEnricher

        loop_thread = threading.get_ident()
        observed = {}

        class _FakeWhois:
            registrar = "Registrar"
            creation_date = None
            expiration_date = None
            name_servers = []
            org = "Example Org"
            country = "US"

        def _fake_lookup(_value):
            observed["thread"] = threading.get_ident()
            return _FakeWhois()

        import sys
        import types

        module = types.ModuleType("whois")
        module.whois = _fake_lookup
        monkeypatch.setitem(sys.modules, "whois", module)

        result = await WhoisEnricher().enrich("example.com", "domain")
        assert result["registrar"] == "Registrar"
        assert observed["thread"] != loop_thread, "WHOIS blocked the event loop"


class TestYARAifyHashHandling:
    async def test_md5_declined_without_a_request(self):
        """Returning None avoids caching a useless error row for every MD5."""
        enricher = YARAifyEnricher("key")
        assert await enricher.enrich("d41d8cd98f00b204e9800998ecf8427e", "hash") is None

    async def test_sha1_declined(self):
        enricher = YARAifyEnricher("key")
        assert await enricher.enrich("a" * 40, "hash") is None


class TestExtractors:
    """Extractors must tolerate empty, partial and complete payloads."""

    def test_nvd_empty_payloads(self):
        assert NVDEnricher()._extract({}) == {"source": "nvd", "found": False}
        assert NVDEnricher()._extract({"vulnerabilities": []})["found"] is False

    def test_nvd_partial_payload_does_not_raise(self):
        result = NVDEnricher()._extract({"vulnerabilities": [{"cve": {}}]})
        assert result["source"] == "nvd"
        assert result["nvd_cvss_v31_score"] is None
        assert result["nvd_cwe_ids"] == []
        assert result["nvd_in_kev"] is False

    def test_nvd_full_payload(self):
        result = NVDEnricher()._extract({"vulnerabilities": [{"cve": {
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "AV:N/AC:L"}}]},
            "weaknesses": [{"description": [{"value": "CWE-502"}, {"value": "NVD-CWE-noinfo"}]}],
            "descriptions": [{"lang": "es", "value": "spanish"},
                             {"lang": "en", "value": "english desc"}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:apache:log4j"}]}]}],
            "cisaExploitAdd": "2021-12-10",
            "vulnStatus": "Analyzed",
            "published": "2021-12-10T10:15:09",
        }}]})
        assert result["nvd_cvss_v31_score"] == 10.0
        assert result["nvd_cvss_v31_severity"] == "CRITICAL"
        assert result["nvd_cwe_ids"] == ["CWE-502"]        # NVD-CWE-* filtered out
        assert result["nvd_description"] == "english desc"  # English preferred
        assert result["nvd_affected_products"] == ["cpe:2.3:a:apache:log4j"]
        assert result["nvd_in_kev"] is True

    def test_cvedetails_empty_and_full(self):
        enricher = CVEDetailsEnricher("token")
        assert enricher._extract({})["found"] is False
        result = enricher._extract({"results": [{
            "cvssV3Score": 9.8, "vendorCvssV3Score": 8.8,
            "advisories": [{"url": "https://vendor/advisory"}],
            "exploitAvailable": True,
            "exploitReferences": [{"url": "https://exploit-db/1"}],
            "affectedProducts": [{"vendor": "apache", "product": "log4j"}],
        }]})
        assert result["cvedetails_cvss_scores"] == {"nvd": 9.8, "vendor": 8.8}
        assert result["cvedetails_exploit_available"] is True
        assert result["cvedetails_advisories"] == ["https://vendor/advisory"]

    def test_yaraify_empty_and_full(self):
        enricher = YARAifyEnricher("key")
        assert enricher._extract({"data": []})["found"] is False
        result = enricher._extract({"data": [{
            "static_results": [{"rule_name": "MALW_Emotet_auto"}, {"rule_name": "win_qakbot_w0"}],
            "clamav_results": ["Win.Trojan.Emotet"],
            "imphash": "abc", "tlsh": "T1", "mime_type": "application/x-dosexec",
            "file_size": 1024, "first_seen": "2026-01-01",
        }]})
        assert result["yaraify_yara_rules"] == ["MALW_Emotet_auto", "win_qakbot_w0"]
        # Prefixes/suffixes stripped and lowercased into family names.
        assert result["yaraify_malware_families"] == ["emotet", "qakbot"]
        assert result["yaraify_imphash"] == "abc"


class TestNoRaiseContract:
    """enrich() must never propagate — a dead source cannot fail the pass."""

    async def test_transport_failure_returns_error_dict(self, monkeypatch):
        import httpx

        class _Boom:
            def __init__(self, *a, **k):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                return False
            async def get(self, *a, **k):
                raise httpx.ConnectError("dns failure")
            async def post(self, *a, **k):
                raise httpx.ConnectError("dns failure")

        monkeypatch.setattr(httpx, "AsyncClient", _Boom)

        nvd = await NVDEnricher().enrich("CVE-2021-44228", "cve")
        assert nvd["source"] == "nvd" and "error" in nvd

        yaraify = await YARAifyEnricher("key").enrich("a" * 64, "hash")
        assert yaraify["source"] == "yaraify" and "error" in yaraify


class TestAssessedContract:
    """Signal names must agree between the enrichers and the scorer, both ways.

    A rename on either side silently zeroes a term: the scorer drops names it does not
    recognise, so a typo in an enricher removes that signal from the denominator
    without any error. This asserts the two vocabularies match exactly.
    """

    @staticmethod
    def _declared_names():
        """Every string literal appearing in an enricher's `assessed` list."""
        import ast
        import importlib
        import inspect
        import pkgutil

        from app import enrichers as pkg

        found = {}
        for mod in pkgutil.iter_modules(pkg.__path__):
            module = importlib.import_module("app.enrichers." + mod.name)
            try:
                tree = ast.parse(inspect.getsource(module))
            except (OSError, TypeError):      # pragma: no cover
                continue
            source_name = getattr(module, "__name__", "").rsplit(".", 1)[-1]
            # The enrichers build `assessed` four different ways, and an extractor
            # that only handled the first silently reported three sources as
            # undeclared. All four are real and all four must be read:
            #   "assessed": [...]            inside a returned dict literal
            #   assessed = [...]             a local built up before the return
            #   result["assessed"] = [...]   assigned into an existing dict
            #   assessed.append("name")      conditional accumulation
            for node in ast.walk(tree):
                values = []
                if isinstance(node, ast.Dict):
                    for k, v in zip(node.keys, node.values):
                        if isinstance(k, ast.Constant) and k.value == "assessed":
                            values.append(v)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if getattr(target, "id", None) == "assessed":
                            values.append(node.value)
                        elif isinstance(target, ast.Subscript):
                            sl = target.slice
                            if isinstance(sl, ast.Constant) and sl.value == "assessed":
                                values.append(node.value)
                elif isinstance(node, ast.Call):
                    fn = node.func
                    if (isinstance(fn, ast.Attribute)
                            and fn.attr in ("append", "extend")
                            and getattr(fn.value, "id", None) == "assessed"):
                        values.extend(node.args)
                # Expand ternaries to their branches only. `["x"] if d.get("y") else []`
                # otherwise contributes "y" from the *condition*, which is a dict key
                # being tested rather than a signal being declared — that produced a
                # false failure naming `country_code` as an unknown signal.
                expanded = []
                for value in values:
                    if isinstance(value, ast.IfExp):
                        expanded.extend([value.body, value.orelse])
                    else:
                        expanded.append(value)
                for value in expanded:
                    for sub in ast.walk(value):
                        # Skip call arguments for the same reason: a signal name is a
                        # bare literal in a list, never something passed to .get().
                        if isinstance(sub, ast.Call):
                            continue
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            found.setdefault(source_name, set()).add(sub.value)
        return found

    def test_every_declared_name_is_known_to_the_scorer(self):
        """A name the scorer does not know contributes nothing — a silent zero."""
        from app.services.scoring_engine import RISK_SIGNALS

        known = {name for signals in RISK_SIGNALS.values() for name in signals}
        unknown = {}
        for module_name, names in self._declared_names().items():
            extra = names - known
            if extra:
                unknown[module_name] = sorted(extra)
        assert not unknown, (
            "these enrichers declare signal names the scorer does not recognise, so "
            "those signals are silently dropped from the risk denominator: "
            + repr(unknown)
            + "\n  scorer knows: " + repr(sorted(known))
        )

    def test_every_scorer_signal_is_declared_by_its_enricher(self):
        """The other direction: a signal nothing declares can never be scored."""
        from app.services.scoring_engine import RISK_SIGNALS

        declared = {n for names in self._declared_names().values() for n in names}
        missing = {}
        for source, signals in RISK_SIGNALS.items():
            absent = set(signals) - declared
            if absent:
                missing[source] = sorted(absent)
        assert not missing, (
            "the scorer defines these signals but no enricher declares them, so they "
            "can only ever be reached through the legacy fallback: " + repr(missing)
        )

    def test_every_scored_source_has_a_registry_entry(self):
        """And every registry source is a real enricher name."""
        from app.enrichers import build_registry
        from app.services.scoring_engine import RISK_SIGNALS

        # build_registry is credential-gated, so compare against the full known set.
        enricher_names = {
            "geoip", "whois", "dns", "reputation", "shodan", "malwarebazaar",
            "nvd", "cvedetails", "yaraify",
        }
        unknown_sources = set(RISK_SIGNALS) - enricher_names
        assert not unknown_sources, (
            "RISK_SIGNALS names sources that are not enrichers: "
            + repr(sorted(unknown_sources))
        )
        # Documented gap, asserted so it is deliberate rather than forgotten.
        # Was {"malwarebazaar", "shodan"} until 2026-07-31; MalwareBazaar gained a
        # branch in Spec 5 §2, so the pin tightens by one rather than being relaxed.
        # Shodan remains unscored deliberately — a recommendation only, because its
        # payload describes exposure (open ports, banners) rather than maliciousness,
        # and every scorer here returns a risk verdict. See PROJECT_SUMMARY.md §8.
        unscored = enricher_names - set(RISK_SIGNALS)
        assert unscored == {"shodan"}, (
            "the set of unscored enrichers changed: " + repr(sorted(unscored))
            + ". Shodan is unscored on purpose; anything else here contributes to "
            "neither term of the risk ratio and is silently invisible to scoring."
        )

    def test_the_point_weights_reproduce_the_previous_per_source_totals(self):
        """Splitting per signal must not change what a fully-assessed source is worth.

        whois 1+2=3, nvd 3+3=6, cvedetails 3+1=4, yaraify 2+1+1=4, geoip 2, dns 2,
        reputation 3 — the same denominators as before the split, so a payload that
        assessed everything scores exactly as it used to.
        """
        from app.services.scoring_engine import RISK_SIGNALS

        # malwarebazaar is not part of that equivalence — it had no branch at all
        # before 2026-07-31, so there is no previous total to reproduce. It is listed
        # here so its source maximum is pinned like the rest. It is 3, not 6:
        # family_attribution moved to the reputation term in Spec 5 section 6
        # (design B-prime), leaving sample_present + vendor_detections.
        expected = {"geoip": 2, "whois": 3, "dns": 2, "reputation": 3,
                    "nvd": 6, "cvedetails": 4, "yaraify": 4, "malwarebazaar": 3}
        actual = {
            source: sum(points for points, _ in signals.values())
            for source, signals in RISK_SIGNALS.items()
        }
        assert actual == expected, (
            "per-source denominator totals changed, so fully-assessed payloads now "
            "score differently: expected " + repr(expected) + " got " + repr(actual)
        )

    async def test_live_enricher_payloads_declare_assessed(self):
        """The shapes the enrichers actually produce, not hand-written fixtures."""
        from app.enrichers.dns_enricher import DNSEnricher
        from app.enrichers.geoip_enricher import GeoIPEnricher

        # GeoIP with no MaxMind database present — the common local case.
        payload = await GeoIPEnricher().enrich("8.8.8.8", "ip")
        assert "assessed" in payload
        assert payload["assessed"] == [], (
            "GeoIP declared a signal despite failing to resolve: " + repr(payload)
        )

        # Reverse DNS declares nothing about fast flux.
        reverse = await DNSEnricher().enrich("127.0.0.1", "ip")
        assert reverse.get("assessed") == [], repr(reverse)
