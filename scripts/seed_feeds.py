#!/usr/bin/env python3
"""Seed initial feed sources into the database."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.database import SyncSessionLocal, sync_engine, Base
from app.models.feed import FeedSource

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


def seed():
    Base.metadata.create_all(bind=sync_engine)
    session = SyncSessionLocal()
    
    try:
        for feed_data in FEEDS:
            existing = session.query(FeedSource).filter(
                FeedSource.slug == feed_data["slug"]
            ).first()
            
            if existing:
                print(f"  Feed '{feed_data['name']}' already exists, skipping.")
                continue
            
            feed = FeedSource(**feed_data)
            session.add(feed)
            print(f"  + Added feed: {feed_data['name']}")
        
        session.commit()
        print(f"\nSeeded {len(FEEDS)} feed sources successfully.")
    except Exception as e:
        session.rollback()
        print(f"Error seeding feeds: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    print("Seeding SENTINEL feed sources...")
    seed()
