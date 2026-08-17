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

FEEDS = [
    {
        "name": "URLhaus",
        "slug": "urlhaus",
        "description": "URLhaus collects and shares malicious URLs used for malware distribution",
        "feed_type": "csv",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "is_enabled": True,
        "sync_frequency": 900,
    },
    {
        "name": "ThreatFox",
        "slug": "threatfox",
        "description": "ThreatFox shares IOCs associated with malware",
        "feed_type": "api",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "api_key_env": "THREATFOX_API_KEY",
        "is_enabled": True,
        "sync_frequency": 1800,
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
        "sync_frequency": 3600,
    },
    {
        "name": "Feodo Tracker",
        "slug": "feodo-tracker",
        "description": "Feodo Tracker tracks botnet C2 infrastructure",
        "feed_type": "csv",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "is_enabled": True,
        "sync_frequency": 1800,
    },
    {
        "name": "Blocklist.de",
        "slug": "blocklist-de",
        "description": "Blocklist.de collects IPs reported for attacks, spam, and abuse",
        "feed_type": "csv",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "is_enabled": True,
        "sync_frequency": 3600,
    },
    {
        "name": "Emerging Threats",
        "slug": "emerging-threats",
        "description": "Emerging Threats compromised IP blocklist",
        "feed_type": "csv",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "is_enabled": True,
        "sync_frequency": 3600,
    },
    {
        "name": "AlienVault OTX",
        "slug": "otx-alienvault",
        "description": "AlienVault Open Threat Exchange - collaborative threat intelligence",
        "feed_type": "api",
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "api_key_env": "OTX_API_KEY",
        "is_enabled": False,
        "sync_frequency": 3600,
    },
    {
        "name": "AbuseIPDB",
        "slug": "abuseipdb",
        "description": "AbuseIPDB blacklist of reported malicious IPs",
        "feed_type": "api",
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "api_key_env": "ABUSEIPDB_API_KEY",
        "is_enabled": False,
        "sync_frequency": 86400,
    },
    {
        "name": "CISA KEV",
        "slug": "cisa-kev",
        "description": "CISA Known Exploited Vulnerabilities - CVEs with confirmed in-the-wild exploitation",
        "feed_type": "api",
        "url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        "is_enabled": True,
        "sync_frequency": 86400,
    },
    {
        "name": "eCrimeLabs Metasploit CVE",
        "slug": "ecrimelabs-metasploit",
        "description": "CVEs with a public Metasploit exploit module",
        "feed_type": "csv",
        "url": "https://feeds.ecrimelabs.net/data/metasploit-cve",
        "is_enabled": True,
        "sync_frequency": 86400,
    },
    {
        "name": "MISP CERT-FR",
        "slug": "misp-cert-fr",
        "description": "MD5 hashes from French ANSSI/CERT-FR government incident response cases",
        "feed_type": "csv",
        "url": "https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv",
        "is_enabled": True,
        "sync_frequency": 21600,
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
