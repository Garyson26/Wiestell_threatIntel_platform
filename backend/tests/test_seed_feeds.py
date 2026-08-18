"""`scripts/seed_feeds.py` runs against a live corpus at deploy, so it needs guarding.

Production holds 8 of the 11 feeds, and **three of those 8 use alias slugs** —
``urlhaus-feed``, ``emerging-threats-feed``, ``feodo-tracker-feed``. The seeder's original
matching was ``FeedSource.slug == feed_data["slug"]`` against the CANONICAL name, which
finds nothing for those three and inserts a second row per feed.

That is not a cosmetic duplicate. ``COUNT(DISTINCT feed_id)`` over ``ioc_sources`` is the
source-diversity term of the threat score, so every indicator ingested afterwards by both
rows would count as two independent sources and score higher. Corpus-wide, silently, from a
deploy step. Verified 2026-08-17 against a replica of production's exact rows: the old
logic inserts ``urlhaus``, ``feodo-tracker`` and ``emerging-threats`` on top of the alias
rows already there, taking 3 rows to 14.

These run in the default tier because they are structural — no database required.
"""

import ast
import inspect
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SEEDER = REPO / "scripts" / "seed_feeds.py"


def _seeder_module():
    import sys

    sys.path.insert(0, str(REPO))
    import scripts.seed_feeds as mod

    return mod


class TestAliasSlugsAreMatchedNotDuplicated:
    def test_every_seeded_slug_resolves_through_the_registry(self):
        """A seed entry whose slug is not in FEED_CONNECTORS can never sync."""
        from app.services.feed_scheduler import FEED_CONNECTORS

        mod = _seeder_module()
        unroutable = [f["slug"] for f in mod.FEEDS if f["slug"] not in FEED_CONNECTORS]
        assert mod.FEEDS, "FEEDS parsed as empty — the check below would be vacuous"
        assert not unroutable, (
            f"these seeded slugs have no FEED_CONNECTORS entry, so a row created for "
            f"them cannot sync: {unroutable}"
        )

    def test_the_alias_groups_actually_group(self):
        """Non-emptiness plus the specific pairings production depends on."""
        mod = _seeder_module()
        groups = mod._alias_groups()
        assert len(groups) >= 11, f"only {len(groups)} slugs grouped; registry not read"

        for canonical, alias in (
            ("urlhaus", "urlhaus-feed"),
            ("emerging-threats", "emerging-threats-feed"),
            ("feodo-tracker", "feodo-tracker-feed"),
        ):
            assert alias in groups[canonical], (
                f"{alias!r} is not grouped with {canonical!r}, so seeding would insert a "
                f"duplicate row for {canonical!r} against production, which holds the "
                f"alias spelling"
            )

    def test_matching_is_not_an_equality_on_the_canonical_slug(self):
        """The specific regression. `slug == feed_data["slug"]` is what duplicated.

        Asserted on the source because the behavioural version needs a database, and
        this failure mode is a one-token edit away at any time.
        """
        source = inspect.getsource(_seeder_module().seed)
        assert "in_(" in source, (
            "seed() no longer matches with an IN over the alias group. If this reverted "
            "to an equality on the canonical slug, seeding production would insert "
            "duplicate rows for urlhaus, emerging-threats and feodo-tracker."
        )


class TestOperationalStateIsNeverOverwritten:
    """A deploy step must not undo an operator's decisions or reset ingest progress."""

    def test_the_two_column_lists_are_disjoint(self):
        mod = _seeder_module()
        for left, right in (("_CODE_DERIVED", "_OPERATIONAL"),
                            ("_CODE_DERIVED", "_REPORTED_ONLY"),
                            ("_OPERATIONAL", "_REPORTED_ONLY")):
            overlap = set(getattr(mod, left)) & set(getattr(mod, right))
            assert not overlap, f"{left} and {right} both claim: {overlap}"

    def test_every_feedsource_column_is_classified(self):
        """A NEW column must be a decision, not a default.

        Without this, adding a column to FeedSource silently leaves it un-updated by the
        seeder — which is the safe default, but an unexamined one. Phase 4 adds cadence
        state to this table, so the question is live rather than hypothetical.
        """
        from app.models.feed import FeedSource

        mod = _seeder_module()
        columns = {c.name for c in FeedSource.__table__.columns}
        assert columns, "no columns read from FeedSource — check would be vacuous"
        classified = set(mod._CODE_DERIVED) | set(mod._OPERATIONAL) | set(mod._REPORTED_ONLY)
        unclassified = columns - classified
        assert not unclassified, (
            f"these FeedSource columns are in neither _CODE_DERIVED nor _OPERATIONAL: "
            f"{sorted(unclassified)}. Decide explicitly: is this column's truth in "
            f"seed_feeds.py (code-derived, refreshed on every run) or in the running "
            f"system (operational, never overwritten)?"
        )

    def test_url_is_reported_rather_than_written(self):
        """The third category. It is code-derived, so the tempting move is to overwrite.

        Three real drifts exist against production, so if this became a write, a deploy
        would silently repoint malwarebazaar, feodo-tracker and otx-alienvault at
        different URLs than the ones they have been ingesting from.
        """
        mod = _seeder_module()
        assert "url" in mod._REPORTED_ONLY
        assert "url" not in mod._CODE_DERIVED, (
            "url moved into the written set; a deploy would now change where feeds fetch "
            "from as a side effect of seeding"
        )

    @pytest.mark.parametrize("column", [
        "is_enabled", "last_sync_at", "last_ingest_watermark", "ioc_count", "slug",
    ])
    def test_the_columns_that_must_survive_a_reseed_are_marked_operational(self, column):
        """Each of these has a concrete failure mode if reset.

        is_enabled           an operator disabling a bad feed must not be overridden
        last_sync_at         drives cadence; resetting it forces an immediate resync
        last_ingest_watermark resetting re-detects the entire history as a rolling gap
        ioc_count            a displayed statistic, not something to zero on deploy
        slug                 ioc_sources references the row; renaming is churn with risk
        """
        assert column in _seeder_module()._OPERATIONAL

    def test_seed_does_not_assign_any_operational_column(self):
        """Source-level check that no `setattr`/assignment targets the preserved set."""
        mod = _seeder_module()
        tree = ast.parse(inspect.getsource(mod.seed))
        setattr_targets = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None)
                if name == "setattr" and len(node.args) >= 2:
                    arg = node.args[1]
                    if isinstance(arg, ast.Constant):
                        setattr_targets.append(arg.value)
        forbidden = set(setattr_targets) & set(mod._OPERATIONAL)
        assert not forbidden, (
            f"seed() writes operational columns by literal name: {forbidden}"
        )


class TestTheMissingFeedsAreStillDefined:
    """The three never seeded to production, and why they matter."""

    @pytest.mark.parametrize("slug", ["cisa-kev", "ecrimelabs-metasploit", "misp-cert-fr"])
    def test_the_unseeded_feeds_are_present_in_the_seed_list(self, slug):
        """Production has no row for these (owner query, 2026-08-17).

        Two of the three — cisa-kev and ecrimelabs-metasploit — are the dedicated CVE
        sources, so production has never ingested either. Dropping them from FEEDS would
        make that permanent by omission rather than by decision.
        """
        assert slug in {f["slug"] for f in _seeder_module().FEEDS}


class TestSeededUrlsMatchTheConnectors:
    """`feed_sources.url` is DESCRIPTIVE — confirmed 2026-08-17, and worth stating.

    No connector's ``__init__`` accepts a url and nothing assigns ``feed.url``; the
    scheduler builds a connector as ``connector_class(api_key=api_key)`` and the class's
    own ``url`` attribute is what ``fetch()`` uses. So this column cannot misroute a
    fetch, which also settles the SSRF question: an admin CAN set it through
    ``FeedCreate``/``FeedUpdate``, but nothing reads it back into a request. (It is still
    redacted on read — see ``schemas/feed.py`` — because an operator could paste a keyed
    URL into it and feed reads are viewer-level.)

    Descriptive is not the same as unimportant: it is shown in the feeds UI, so a wrong
    value misinforms an operator diagnosing a feed. This guard keeps the two in step,
    and it earned its place immediately — ``feodo-tracker`` was seeded as
    ``ipblocklist_recommended.txt`` while the connector fetched ``ipblocklist.csv``.
    Production happened to hold the correct value, so seeding ``url`` would have replaced
    a right value with a wrong one.
    """

    def test_every_seeded_url_matches_its_connector_class_attribute(self):
        import importlib

        from app.services.feed_scheduler import FEED_CONNECTORS

        mod = _seeder_module()
        checked, mismatches = 0, []
        for feed in mod.FEEDS:
            slug, seeded = feed["slug"], feed.get("url")
            if not seeded:
                continue
            path = FEED_CONNECTORS[slug]
            module_path, class_name = path.rsplit(".", 1)
            connector_url = getattr(
                getattr(importlib.import_module(module_path), class_name), "url", None
            )
            checked += 1
            if connector_url and seeded != connector_url:
                mismatches.append(f"{slug}\n      seed: {seeded}\n      conn: {connector_url}")

        assert checked >= 10, f"only {checked} urls compared; the loop is not running"
        assert not mismatches, (
            "seeded url disagrees with the connector that actually fetches:\n  "
            + "\n  ".join(mismatches)
            + "\n\nThe connector's class attribute is authoritative; fix the seed entry."
        )

    def test_no_connector_accepts_a_url_argument(self):
        """The SSRF question, asserted rather than left as prose."""
        import importlib
        import inspect

        from app.services.feed_scheduler import FEED_CONNECTORS

        offenders, checked = [], 0
        for path in set(FEED_CONNECTORS.values()):
            module_path, class_name = path.rsplit(".", 1)
            cls = getattr(importlib.import_module(module_path), class_name)
            checked += 1
            if "url" in inspect.signature(cls.__init__).parameters:
                offenders.append(class_name)
        assert checked >= 10, f"only {checked} connectors inspected"
        assert not offenders, (
            f"{offenders} accept a url at construction. If the scheduler ever passes "
            "feed.url there, an admin-settable column becomes an SSRF primitive on an "
            "authenticated endpoint — feed CRUD lets an admin write any value."
        )


class TestAFreshSeedEnablesEveryFeed:
    """A feed seeded disabled never syncs, and nothing reports it as a problem.

    `otx-alienvault` and `abuseipdb` seeded as `is_enabled: False` until 2026-08-17 —
    almost certainly a leftover from when a keyed feed could not work without credentials
    present at seed time. Found by the deploy rehearsal, which ran the sequence against an
    empty database and got 9 of 11 enabled.

    **This is not confined to disaster recovery.** The three feeds Section G adds are NEW
    rows, so whatever this file declares is exactly what production gets. A `False` on one
    of those would produce a feed that never syncs, and the only symptom would be a CVE
    population that stayed empty — indistinguishable from a source having nothing to say.

    `is_enabled` is `_OPERATIONAL`, so this changes nothing for feeds that already exist;
    an operator's decision to disable a misbehaving feed still survives a reseed.
    """

    def test_every_seeded_feed_is_enabled(self):
        mod = _seeder_module()
        assert mod.FEEDS, "FEEDS is empty; the check would be vacuous"
        disabled = [f["slug"] for f in mod.FEEDS if f.get("is_enabled") is not True]
        assert not disabled, (
            f"these feeds seed DISABLED and would never sync in a fresh environment: "
            f"{disabled}. If a feed genuinely should ship off, say so explicitly here "
            "with the reason — silence reads as an oversight, which is what it was."
        )

    def test_a_fresh_seed_would_produce_eleven_enabled_feeds(self):
        """The rehearsal's assertion, pinned: 11/11, not 9/11."""
        mod = _seeder_module()
        enabled = [f for f in mod.FEEDS if f.get("is_enabled") is True]
        assert len(enabled) == 11, (
            f"a fresh seed produces {len(enabled)} enabled feeds, expected 11"
        )

    @pytest.mark.parametrize("slug", ["cisa-kev", "ecrimelabs-metasploit", "misp-cert-fr"])
    def test_the_section_g_feeds_are_enabled(self, slug):
        """Called out separately because these are the rows G actually creates.

        For the other eight, production already holds an enabled row and the seeder
        preserves it — so a wrong default there is latent. For these three there is no
        existing row to preserve, so the declaration here IS the production value.
        """
        mod = _seeder_module()
        feed = next(f for f in mod.FEEDS if f["slug"] == slug)
        assert feed.get("is_enabled") is True, (
            f"{slug} seeds disabled, so Section G would create a feed that never syncs "
            "and the CVE/hash population would stay empty with no error anywhere"
        )

    @pytest.mark.parametrize("slug", ["otx-alienvault", "abuseipdb"])
    def test_the_two_reputation_feeds_are_enabled(self, slug):
        """These two are why the default mattered.

        `_OTX_TYPES` covers hash; `_ABUSEIPDB_TYPES` is {"ip"} — so OTX is the only
        reputation provider covering hashes at all after VirusTotal's removal, and the
        two together are the only pair that can corroborate an IP verdict, which matters
        because reputation aggregates as MAX across providers.
        """
        mod = _seeder_module()
        feed = next(f for f in mod.FEEDS if f["slug"] == slug)
        assert feed.get("is_enabled") is True
