"""Feodo Tracker (abuse.ch) feed connector — free, no API key required."""

import csv
import io
from datetime import datetime
from typing import Any, List, Dict, Optional

from app.feeds.base import BaseFeed

# CSV endpoint provides malware family, C2 status, port, and timestamps
_CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


class FeodoTrackerFeed(BaseFeed):
    name = "Feodo Tracker"
    slug = "feodo-tracker"
    feed_type = "csv"
    url = _CSV_URL
    description = "Feodo Tracker tracks botnet C2 infrastructure"
    requires_api_key = False
    default_sync_frequency = 1800

    async def fetch(self) -> Any:
        response = await self._fetch_url(self.url)
        return response.text

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Parse Feodo Tracker CSV.
        Columns: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
        """
        iocs = []
        reader = csv.reader(io.StringIO(raw_data))

        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 6:
                continue

            try:
                first_seen_str = row[0].strip().strip('"')
                dst_ip        = row[1].strip().strip('"')
                dst_port      = row[2].strip().strip('"')
                c2_status     = row[3].strip().strip('"')  # "Online" or "Offline"
                last_online   = row[4].strip().strip('"')
                malware       = row[5].strip().strip('"')  # Dridex, Emotet, TrickBot …

                if not dst_ip:
                    continue

                # Online C2s are an active threat; bump score accordingly
                threat_score = 90 if c2_status.lower() == "online" else 70

                tags = ["feodo-tracker", "botnet", "c2"]
                if malware:
                    tags.append(malware.lower())

                first_seen: Optional[datetime] = None
                try:
                    first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

                iocs.append(self._make_ioc(
                    ioc_type="ip",
                    value=dst_ip,
                    tags=tags,
                    threat_score=threat_score,
                    confidence=90,
                    first_seen=first_seen,
                    metadata={
                        "source": "feodo-tracker",
                        "threat_type": "botnet_c2",
                        "malware": malware,
                        "dst_port": dst_port,
                        "c2_status": c2_status,
                        "last_online": last_online,
                    },
                    mitre_techniques=["T1071", "T1573"],
                ))
            except (IndexError, ValueError):
                continue

        return iocs
