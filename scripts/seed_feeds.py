#!/usr/bin/env python3
"""Seed feed sources into the database. Idempotent, and safe against a live corpus.

WHAT PRODUCTION ACTUALLY LOOKS LIKE (owner query, 2026-08-17)
-------------------------------------------------------------
``feed_sources`` holds **8 rows**, all enabled, against the 11 defined here. The three
never seeded are ``cisa-kev``, ``ecrimelabs-metasploit`` and ``misp-cert-fr`` — the feeds
added in the original review session. Production has therefore **never ingested CISA KEV
or eCrimeLabs**, which are the two dedicated CVE sources.

**Three of the eight rows use ALIAS slugs**, not the canonical ones defined here::

    emerging-threats-feed    (canonical: emerging-threats)
    feodo-tracker-feed       (canonical: feodo-tracker)
    urlhaus-feed             (canonical: urlhaus)

That mismatch is why this script was rewritten. The previous version matched on the
canonical slug with an exact ``==`` and skipped on a hit, which against production would
have found no row for ``urlhaus``, ``emerging-threats`` or ``feodo-tracker`` and **INSERTED
THREE DUPLICATES** — a second ``feed_sources`` row per feed, pointing at the same
connector. That is not cosmetic: ``COUNT(DISTINCT feed_id)`` over ``ioc_sources`` is the
source-diversity term of the threat score, so every indicator subsequently ingested by
both rows would score as two independent sources. It would have inflated scores corpus-wide
and silently.

So matching is by **alias group**, derived from ``FEED_CONNECTORS`` rather than hardcoded:
two slugs that resolve to the same connector class are the same feed.

WHAT IT WRITES, AND WHAT IT REFUSES TO TOUCH
--------------------------------------------
On an existing row it updates only **code-derived** columns — the ones whose truth lives
in this file — and never operational state:

  updated   name, description, feed_type, api_key_env, sync_frequency (the cadence)
  PRESERVED is_enabled, last_sync_at, last_sync_status, last_sync_error,
            last_ingest_watermark, last_ingest_gap, ioc_count, config, created_at, slug

``is_enabled`` is preserved deliberately: an operator disabling a misbehaving feed must not
have it re-enabled by a deploy step. ``last_ingest_watermark`` likewise — resetting it
would make the rolling-window continuity check (revision ``f6a7b8c90003``) re-detect the
entire history as a gap. And the row's existing ``slug`` is kept rather than rewritten to
the canonical spelling, because ``ioc_sources`` rows reference it by id and the alias
resolves through ``FEED_CONNECTORS`` perfectly well — renaming would be churn with a
migration-shaped risk and no benefit.

``url`` is **reported, not overwritten**. It is code-derived, but changing where a feed
fetches from is a behaviour change that should be a decision rather than a side effect of
running a seed script.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.database import SyncSessionLocal, sync_engine, Base
from app.models.feed import FeedSource
from app.services.feed_scheduler import FEED_CONNECTORS

#: Columns whose truth lives in this file and may be refreshed on an existing row.
_CODE_DERIVED = ("name", "description", "feed_type", "api_key_env", "sync_frequency")

#: Code-derived but behaviour-affecting: reported on drift, never written. A third
#: category rather than a fudge — changing where a feed fetches from is a decision, and
#: silently repointing it during a deploy step is how a feed starts ingesting the wrong
#: thing. Three real drifts exist against production today (malwarebazaar,
#: feodo-tracker-feed, otx-alienvault), so this path is exercised, not theoretical.
_REPORTED_ONLY = ("url",)

#: Columns that belong to the running system. Never written on an existing row.
_OPERATIONAL = (
    "is_enabled", "last_sync_at", "last_sync_status", "last_sync_error",
    "last_ingest_watermark", "last_ingest_gap", "ioc_count", "config",
    "created_at", "slug", "id",
    # Phase 4 Section A (revision a7b8c9d00004). All five are machine-managed and
    # all five are operational, but the reasons differ and are worth stating because
    # `sync_frequency` sits one line above in _CODE_DERIVED and looks similar:
    #
    #   last_attempt_at       scheduling state. Resetting it makes every feed
    #                         instantly overdue, so a deploy would fire all 8 at once
    #                         against a shared host.
    #   consecutive_failures  back-off state. Zeroing it on deploy would restart
    #                         aggressive retries against a feed that is still down.
    #   sync_cursor           OTX's modified_since position. Clearing it means a full
    #                         re-fetch from the beginning of history.
    #   http_etag /           conditional-request state. Clearing them costs a
    #   http_last_modified    needless full download, not correctness.
    #
    # The cadence VALUE (`sync_frequency`) is code-derived and refreshed; the cadence
    # STATE (`last_attempt_at`) is operational and preserved. That distinction is the
    # whole reason the split exists.
    "last_attempt_at", "consecutive_failures", "sync_cursor",
    "http_etag", "http_last_modified",
)


def _alias_groups() -> dict:
    """slug -> every slug resolving to the same connector, from the live registry.

    Derived rather than hardcoded so a new alias added to ``FEED_CONNECTORS`` is picked
    up here automatically. A second copy of this mapping would be one more thing to keep
    in step, and the drift between the registry and the seed list is the bug this whole
    docstring is about.
    """
    by_target: dict = {}
    for slug, target in FEED_CONNECTORS.items():
        by_target.setdefault(target, set()).add(slug)
    return {slug: by_target[target] for target, slugs in
            ((t, s) for t, s in by_target.items()) for slug in slugs}


# ── CADENCE — the OPERATIONAL value, not the connector's aspiration ───────────
#
# ASSIGNED 2026-08-18. Until then every entry here simply mirrored its connector's
# `default_sync_frequency`, and those numbers were written for the ASYNCIO SCHEDULER,
# which ticks every 60 seconds. That scheduler is implemented and never started; the live
# path is an external cron firing every 6 HOURS. Against a 6-hourly cron a declared 900s
# or 1800s is meaningless -- it advertises a 15- or 30-minute cadence the platform cannot
# deliver, and 8 of 11 feeds were indistinguishable from each other in effect.
#
# The seeded value must therefore describe what actually happens.
#
# BUT IT MUST NOT BE AN EXACT MULTIPLE OF THE CRON PERIOD, and this is measured rather
# than reasoned. GitHub Actions DELAYS scheduled runs (never advances them) and the delay
# VARIES run to run, so a feed declared at exactly 6h skips whenever one firing is
# delayed more than the next. Simulated over 200 firings:
#
#   declared   delay 0   delay 5min   delay 30min
#   21600 (6h)   6.0h       9.3h         9.4h      <-- 71 of 200 runs SKIPPED
#   18000 (5h)   6.0h       6.0h         6.0h
#   86400 (24h) 24.0h      27.3h        27.0h      <-- same defect at 4x
#   79200 (22h) 24.0h      24.0h        24.0h
#
# That is the §1.1 skip-alignment defect, reintroduced by an honest-looking number. So a
# cadence is declared one jitter margin BELOW the multiple of the cron period it wants:
#
#   18000 (5h)  -> delivered every firing      = 6h
#   79200 (22h) -> delivered every 4th firing  = 24h
#
# `tests/test_deploy_config.py` enforces the band: the margin must be large enough to
# absorb delay and small enough that the declared value does not lie about the cadence.
FEEDS = [
    {
        "name": "URLhaus",
        "slug": "urlhaus",
        "description": "URLhaus collects and shares malicious URLs used for malware distribution",
        "feed_type": "csv",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "is_enabled": True,
        "sync_frequency": 18000,
    },
    {
        "name": "ThreatFox",
        "slug": "threatfox",
        "description": "ThreatFox shares IOCs associated with malware",
        "feed_type": "api",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "api_key_env": "THREATFOX_API_KEY",
        "is_enabled": True,
        "sync_frequency": 18000,
    },
    {
        "name": "MalwareBazaar",
        "slug": "malwarebazaar",
        "description": "MalwareBazaar malware sample hashes (keyless CSV export)",
        "feed_type": "csv",
        # The keyless export. Verified 2026-07-30: HTTP 200, 881 samples over a
        # measured 47.78-hour window. No api_key_env: an abuse.ch key is additive
        # (query API + certificate blocklist) and set via MALWAREBAZAAR_API_KEY.
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "is_enabled": True,
        # 1 hour, against a 47.78h window — samples cannot slip between syncs
        # until this exceeds ~24h. See MalwareBazaarFeed._PUBLIC_WINDOW_HOURS.
        "sync_frequency": 18000,
    },
    {
        "name": "Feodo Tracker",
        "slug": "feodo-tracker",
        "description": "Feodo Tracker tracks botnet C2 infrastructure",
        "feed_type": "csv",
        # Must match FeodoTrackerFeed.url -- the connector's class attribute is what
        # actually fetches; this column is descriptive only. This said
        # ipblocklist_recommended.txt while the connector fetched ipblocklist.csv,
        # found 2026-08-17. Production already held the correct value, so seeding url
        # would have overwritten a right value with a wrong one.
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "is_enabled": True,
        "sync_frequency": 18000,
    },
    {
        "name": "Blocklist.de",
        "slug": "blocklist-de",
        "description": "Blocklist.de collects IPs reported for attacks, spam, and abuse",
        "feed_type": "csv",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "is_enabled": True,
        "sync_frequency": 18000,
    },
    {
        "name": "Emerging Threats",
        "slug": "emerging-threats",
        "description": "Emerging Threats compromised IP blocklist",
        "feed_type": "csv",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "is_enabled": True,
        "sync_frequency": 18000,
    },
    {
        "name": "AlienVault OTX",
        "slug": "otx-alienvault",
        "description": "AlienVault Open Threat Exchange - collaborative threat intelligence",
        "feed_type": "api",
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "api_key_env": "OTX_API_KEY",
        # ENABLED 2026-08-17. It seeded as False, which almost certainly dates from when
        # a keyed feed could not work without credentials being present at seed time.
        # That reasoning no longer holds and the cost is now concrete: OTX is the ONLY
        # reputation provider that covers hashes at all (_OTX_TYPES includes "hash",
        # _ABUSEIPDB_TYPES is {"ip"}), so a fresh environment seeding it disabled has no
        # hash reputation whatsoever after VirusTotal's removal.
        "is_enabled": True,
        "sync_frequency": 18000,
    },
    {
        "name": "AbuseIPDB",
        "slug": "abuseipdb",
        "description": "AbuseIPDB blacklist of reported malicious IPs",
        "feed_type": "api",
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "api_key_env": "ABUSEIPDB_API_KEY",
        # ENABLED 2026-08-17, same reasoning as OTX above. AbuseIPDB and OTX are the only
        # two providers that both cover IPs, and reputation aggregates as MAX across
        # providers -- so seeding this disabled leaves IP reputation resting on a single
        # source with nothing to corroborate it.
        "is_enabled": True,
        "sync_frequency": 79200,
    },
    {
        "name": "CISA KEV",
        "slug": "cisa-kev",
        "description": "CISA Known Exploited Vulnerabilities - CVEs with confirmed in-the-wild exploitation",
        "feed_type": "api",
        # Must match CISAKEVFeed.url. Changed 2026-08-17 with the connector: CISA's
        # canonical URL is tried first and the GitHub mirror is the fallback, because
        # the mirror is now the one that rate-limits.
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "is_enabled": True,
        "sync_frequency": 79200,
    },
    {
        "name": "eCrimeLabs Metasploit CVE",
        "slug": "ecrimelabs-metasploit",
        "description": "CVEs with a public Metasploit exploit module",
        "feed_type": "csv",
        "url": "https://feeds.ecrimelabs.net/data/metasploit-cve",
        "is_enabled": True,
        "sync_frequency": 79200,
    },
    {
        "name": "MISP CERT-FR",
        "slug": "misp-cert-fr",
        "description": "MD5 hashes from French ANSSI/CERT-FR government incident response cases",
        "feed_type": "csv",
        "url": "https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv",
        "is_enabled": True,
        "sync_frequency": 18000,
    },
    # NOTE: PhishTank and VirusTotal were removed on 2026-07-29 along with their
    # connector modules, leaving 11 feeds. Any existing `feed_sources` rows for
    # them are soft-disabled by revision e5f6a7b80002 rather than deleted —
    # `ioc_sources` still links them to indicators they contributed, and deleting
    # the rows would lower `source_count` for each of those.
]


def seed(dry_run: bool = False):
    Base.metadata.create_all(bind=sync_engine)
    session = SyncSessionLocal()
    groups = _alias_groups()

    inserted = updated = unchanged = 0
    url_drift = []

    try:
        for feed_data in FEEDS:
            canonical = feed_data["slug"]
            # Match on ANY slug that resolves to the same connector, so an alias row
            # such as `urlhaus-feed` is recognised as the existing `urlhaus` feed
            # instead of being duplicated.
            candidates = sorted(groups.get(canonical, {canonical}))
            existing = session.query(FeedSource).filter(
                FeedSource.slug.in_(candidates)
            ).first()

            if existing is None:
                if not dry_run:
                    session.add(FeedSource(**feed_data))
                inserted += 1
                print(f"  + INSERT {canonical:<24} (no row for any of {candidates})")
                continue

            note = "" if existing.slug == canonical else f" [alias row: {existing.slug!r}]"

            changes = {}
            for column in _CODE_DERIVED:
                if column not in feed_data:
                    continue
                if getattr(existing, column) != feed_data[column]:
                    changes[column] = (getattr(existing, column), feed_data[column])

            if feed_data.get("url") and existing.url != feed_data["url"]:
                url_drift.append((existing.slug, existing.url, feed_data["url"]))

            if not changes:
                unchanged += 1
                print(f"  = unchanged {canonical:<20}{note}")
                continue

            if not dry_run:
                for column, (_, new) in changes.items():
                    setattr(existing, column, new)
            updated += 1
            detail = ", ".join(f"{c}: {o!r} -> {n!r}" for c, (o, n) in changes.items())
            print(f"  ~ UPDATE {canonical:<24}{note}  {detail}")

        if dry_run:
            session.rollback()
        else:
            session.commit()

        print(f"\n  inserted {inserted}   updated {updated}   unchanged {unchanged}"
              f"   ({'DRY RUN, rolled back' if dry_run else 'committed'})")

        if url_drift:
            print("\n  URL DRIFT — reported, NOT written. Changing where a feed fetches")
            print("  from is a decision, not a side effect of seeding:")
            for slug, old, new in url_drift:
                print(f"    {slug}\n      db:   {old}\n      code: {new}")

        print("\n  Preserved on every existing row: " + ", ".join(_OPERATIONAL))
    except Exception as e:
        session.rollback()
        print(f"Error seeding feeds: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    print("Seeding SENTINEL feed sources..." + ("  (DRY RUN)" if dry else ""))
    seed(dry_run=dry)
