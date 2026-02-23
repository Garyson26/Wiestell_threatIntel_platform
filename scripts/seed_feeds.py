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
        "is_enabled": True,
        "sync_frequency": 1800,
    },
    {
        "name": "MalwareBazaar",
        "slug": "malwarebazaar",
        "description": "MalwareBazaar shares malware samples and hashes",
        "feed_type": "api",
        "url": "https://mb-api.abuse.ch/api/v1/",
        "is_enabled": True,
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
        "name": "PhishTank",
        "slug": "phishtank",
        "description": "PhishTank verified phishing URLs",
        "feed_type": "api",
        "url": "http://data.phishtank.com/data/online-valid.json",
        "api_key_env": "PHISHTANK_API_KEY",
        "is_enabled": False,
        "sync_frequency": 3600,
    },
    {
        "name": "VirusTotal",
        "slug": "virustotal",
        "description": "VirusTotal file and URL analysis (lookup only)",
        "feed_type": "api",
        "url": "https://www.virustotal.com/api/v3",
        "api_key_env": "VT_API_KEY",
        "is_enabled": False,
        "sync_frequency": 3600,
    },
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
