#!/usr/bin/env python3
"""Generate realistic sample IOC data for demonstration."""

import sys
import os
import random
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.database import SyncSessionLocal, sync_engine, Base
from app.models.ioc import IOC
from app.models.ioc_relationship import IOCRelationship
from app.models.enrichment import Enrichment
from app.models.ioc_source import IOCSource
from app.models.feed import FeedSource

SAMPLE_IPS = [
    "185.220.101.42", "45.155.205.233", "194.26.192.64", "91.219.236.222",
    "23.129.64.210", "185.56.83.83", "171.25.193.77", "162.247.74.74",
    "198.96.155.3", "199.195.250.77", "104.244.76.13", "209.141.58.146",
    "185.100.87.174", "178.73.215.171", "193.218.118.190", "80.67.172.162",
    "51.15.43.205", "195.176.3.24", "185.129.61.1", "166.70.207.2",
    "103.251.167.10", "45.61.185.90", "89.163.243.88", "95.214.53.70",
    "212.21.66.6", "185.83.214.69", "188.68.58.16", "31.172.83.152",
    "203.0.113.50", "198.51.100.23", "172.16.254.1", "10.0.0.1",
]

SAMPLE_DOMAINS = [
    "evil-malware.com", "phish-bank-login.net", "c2-server.xyz",
    "malicious-payload.org", "steal-creds.ru", "botnet-controller.cn",
    "fake-update.com", "crypto-miner-pool.net", "ransomware-pay.onion.ws",
    "exploit-kit-landing.tk", "drive-by-download.ml", "apt28-infra.cc",
    "watering-hole.co", "spear-phish.biz", "data-exfil.io",
]

SAMPLE_HASHES = [
    "e99a18c428cb38d5f260853678922e03", "5d41402abc4b2a76b9719d911017c592",
    "098f6bcd4621d373cade4e832627b4f6", "d8578edf8458ce06fbc5bb76a58c5ca4",
    "7c6a180b36896a65c4c3a8e2b9c3c2a1", "6cb75f652a9b52798eb6cf2201057c73",
    "8621ffdbc5698829397d97767ac13db3", "3c59dc048e8850243be8079a5c74d079",
    "a87ff679a2f3e71d9181a67b7542122c", "e4da3b7fbbce2345d7772b0674a318d5",
    "1679091c5a880faf6fb5e6087eb1b2dc", "8f14e45fceea167a5a36dedd4bea2543",
]

SAMPLE_URLS = [
    "http://evil-malware.com/payload.exe",
    "https://phish-bank-login.net/login.php",
    "http://c2-server.xyz:8443/beacon",
    "https://malicious-payload.org/dropper.js",
    "http://fake-update.com/chrome-update.exe",
    "https://crypto-miner-pool.net/xmrig/config.json",
]

TAGS_POOL = [
    "malware", "phishing", "c2", "botnet", "ransomware", "apt", "trojan",
    "exploit", "dropper", "miner", "spam", "bruteforce", "ddos", "scanner",
    "backdoor", "rat", "emotet", "trickbot", "cobalt-strike", "apt28",
]

MITRE_TECHNIQUES = [
    "T1566", "T1190", "T1071", "T1059", "T1027", "T1053", "T1547",
    "T1078", "T1021", "T1055", "T1105", "T1573", "T1095", "T1036",
]

COUNTRIES = ["US", "CN", "RU", "DE", "NL", "FR", "GB", "UA", "IR", "KP", "AE", "IN", "BR"]


def generate():
    Base.metadata.create_all(bind=sync_engine)
    session = SyncSessionLocal()

    try:
        iocs_created = []
        now = datetime.now(timezone.utc)

        # Generate IP IOCs
        for ip in SAMPLE_IPS:
            score = random.randint(20, 95)
            days_ago = random.randint(0, 30)
            tags = random.sample(TAGS_POOL, random.randint(1, 4))
            techniques = random.sample(MITRE_TECHNIQUES, random.randint(0, 3))
            country = random.choice(COUNTRIES)

            ioc = IOC(
                type="ip",
                value=ip,
                threat_score=score,
                confidence=random.randint(40, 95),
                first_seen=now - timedelta(days=days_ago + random.randint(1, 60)),
                last_seen=now - timedelta(days=days_ago, hours=random.randint(0, 23)),
                sighting_count=random.randint(1, 200),
                tags=tags,
                metadata_={"country_code": country, "source": "sample_data"},
                mitre_techniques=techniques,
            )
            session.add(ioc)
            iocs_created.append(ioc)

        # Generate Domain IOCs
        for domain in SAMPLE_DOMAINS:
            score = random.randint(30, 90)
            days_ago = random.randint(0, 30)
            tags = random.sample(TAGS_POOL, random.randint(1, 4))

            ioc = IOC(
                type="domain",
                value=domain,
                threat_score=score,
                confidence=random.randint(40, 90),
                first_seen=now - timedelta(days=days_ago + random.randint(1, 90)),
                last_seen=now - timedelta(days=days_ago),
                sighting_count=random.randint(1, 50),
                tags=tags,
                metadata_={"source": "sample_data"},
                mitre_techniques=random.sample(MITRE_TECHNIQUES, random.randint(0, 2)),
            )
            session.add(ioc)
            iocs_created.append(ioc)

        # Generate Hash IOCs
        for h in SAMPLE_HASHES:
            score = random.randint(50, 95)
            tags = ["malware"] + random.sample(TAGS_POOL, random.randint(1, 3))

            ioc = IOC(
                type="hash",
                value=h,
                threat_score=score,
                confidence=random.randint(60, 95),
                first_seen=now - timedelta(days=random.randint(1, 60)),
                last_seen=now - timedelta(days=random.randint(0, 10)),
                sighting_count=random.randint(1, 100),
                tags=tags,
                metadata_={"hash_type": "md5", "source": "sample_data"},
            )
            session.add(ioc)
            iocs_created.append(ioc)

        # Generate URL IOCs
        for url in SAMPLE_URLS:
            score = random.randint(60, 95)
            tags = random.sample(TAGS_POOL, random.randint(1, 3))

            ioc = IOC(
                type="url",
                value=url,
                threat_score=score,
                confidence=random.randint(50, 90),
                first_seen=now - timedelta(days=random.randint(1, 30)),
                last_seen=now - timedelta(days=random.randint(0, 5)),
                sighting_count=random.randint(1, 30),
                tags=tags,
                metadata_={"source": "sample_data"},
                mitre_techniques=random.sample(MITRE_TECHNIQUES, random.randint(0, 2)),
            )
            session.add(ioc)
            iocs_created.append(ioc)

        session.flush()

        # Create some relationships
        for _ in range(min(30, len(iocs_created) // 2)):
            src = random.choice(iocs_created)
            tgt = random.choice(iocs_created)
            if src.id != tgt.id:
                rel_type = random.choice([
                    "resolves_to", "communicates_with", "drops",
                    "hosts", "associated_with",
                ])
                try:
                    rel = IOCRelationship(
                        source_ioc_id=src.id,
                        target_ioc_id=tgt.id,
                        relationship_type=rel_type,
                        confidence=random.randint(30, 90),
                    )
                    session.add(rel)
                    session.flush()
                except Exception:
                    session.rollback()
                    session.flush()

        # Create IOC sources linking to seeded feeds
        feeds = session.query(FeedSource).all()
        if feeds:
            for ioc in iocs_created:
                num_sources = random.randint(1, min(3, len(feeds)))
                for feed in random.sample(feeds, num_sources):
                    try:
                        src = IOCSource(
                            ioc_id=ioc.id,
                            feed_id=feed.id,
                            raw_data={"value": ioc.value, "source": feed.slug},
                        )
                        session.add(src)
                        session.flush()
                    except Exception:
                        session.rollback()
                        session.flush()
            print(f"  Created IOC source links to {len(feeds)} feeds.")

        # Create enrichments per IOC type
        for ioc in iocs_created:
            if ioc.type == "ip":
                country = ioc.metadata_.get("country_code", "US") if ioc.metadata_ else "US"
                session.add(Enrichment(
                    ioc_id=ioc.id,
                    source="geoip",
                    data={
                        "country": country,
                        "city": random.choice(["Moscow", "Beijing", "Berlin", "New York", "London", "Tehran", "Kyiv"]),
                        "latitude": round(random.uniform(-60, 60), 4),
                        "longitude": round(random.uniform(-180, 180), 4),
                        "asn": f"AS{random.randint(1000, 65000)}",
                        "org": random.choice(["Hetzner Online", "OVH SAS", "DigitalOcean", "Amazon AWS", "Rostelecom", "China Telecom"]),
                    },
                ))
                session.add(Enrichment(
                    ioc_id=ioc.id,
                    source="whois",
                    data={
                        "registrar": random.choice(["RIPE NCC", "ARIN", "APNIC", "LACNIC"]),
                        "net_range": f"{ioc.value.rsplit('.', 1)[0]}.0/24",
                        "org_name": random.choice(["Hetzner Online GmbH", "OVH Hosting", "DigitalOcean LLC", "Amazon.com Inc."]),
                        "abuse_contact": "abuse@example.com",
                    },
                ))
            elif ioc.type == "domain":
                session.add(Enrichment(
                    ioc_id=ioc.id,
                    source="whois",
                    data={
                        "registrar": random.choice(["Namecheap Inc.", "GoDaddy", "Tucows", "Eranet International"]),
                        "creation_date": (now - timedelta(days=random.randint(30, 365))).isoformat(),
                        "expiry_date": (now + timedelta(days=random.randint(30, 365))).isoformat(),
                        "name_servers": [f"ns{i}.example.com" for i in range(1, 3)],
                        "registrant_country": random.choice(COUNTRIES),
                    },
                ))
                session.add(Enrichment(
                    ioc_id=ioc.id,
                    source="dns",
                    data={
                        "a_records": [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"],
                        "mx_records": [f"mail.{ioc.value}"],
                        "ns_records": [f"ns1.{ioc.value}", f"ns2.{ioc.value}"],
                        "txt_records": ["v=spf1 -all"],
                    },
                ))
            elif ioc.type == "hash":
                session.add(Enrichment(
                    ioc_id=ioc.id,
                    source="reputation",
                    data={
                        "malware_family": random.choice(["Emotet", "TrickBot", "QakBot", "IcedID", "Cobalt Strike", "AgentTesla"]),
                        "detections": f"{random.randint(20, 65)}/72",
                        "first_submission": (now - timedelta(days=random.randint(10, 180))).isoformat(),
                        "file_type": random.choice(["PE32 executable", "Microsoft Word Document", "PDF document", "ELF executable"]),
                        "file_size": random.randint(10000, 5000000),
                    },
                ))
            elif ioc.type == "url":
                session.add(Enrichment(
                    ioc_id=ioc.id,
                    source="dns",
                    data={
                        "resolved_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                        "status_code": random.choice([200, 301, 403, 404]),
                        "content_type": random.choice(["text/html", "application/octet-stream", "application/javascript"]),
                    },
                ))
                session.add(Enrichment(
                    ioc_id=ioc.id,
                    source="reputation",
                    data={
                        "threat_label": random.choice(["malware_distribution", "phishing", "exploit_kit", "c2_communication"]),
                        "blacklisted_by": random.sample(["Google Safe Browsing", "PhishTank", "URLhaus", "Spamhaus"], random.randint(1, 3)),
                        "risk_score": random.randint(60, 100),
                    },
                ))
        session.flush()
        print(f"  Created enrichment records for IOCs.")

        session.commit()
        print(f"Generated {len(iocs_created)} sample IOCs with relationships, sources, and enrichments.")

    except Exception as e:
        session.rollback()
        print(f"Error generating sample data: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    print("Generating SENTINEL sample data...")
    generate()
