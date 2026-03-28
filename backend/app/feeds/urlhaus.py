"""URLhaus (abuse.ch) feed connector — free, no API key required."""

import csv
import io
from datetime import datetime
from typing import Any, List, Dict, Optional

from app.feeds.base import BaseFeed


class URLhausFeed(BaseFeed):
    name = "URLhaus"
    slug = "urlhaus"
    feed_type = "csv"
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    description = "URLhaus collects and shares malicious URLs used for malware distribution"
    requires_api_key = False
    default_sync_frequency = 900

    async def fetch(self) -> Any:
        response = await self._fetch_url(self.url)
        return response.text

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Parse URLhaus CSV.
        Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        """
        iocs = []
        reader = csv.reader(io.StringIO(raw_data))

        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 8:
                continue

            try:
                dateadded  = row[1].strip().strip('"')
                url        = row[2].strip().strip('"')
                url_status = row[3].strip().strip('"')
                last_online = row[4].strip().strip('"')
                threat     = row[5].strip().strip('"')
                tags_str   = row[6].strip().strip('"')

                if not url or not url.startswith("http"):
                    continue

                tags = ["urlhaus", "malware-distribution"]
                if tags_str:
                    tags.extend([t.strip() for t in tags_str.split(",") if t.strip()])
                if threat:
                    tags.append(threat.lower())

                score = 65
                if url_status == "online":
                    score = 80
                elif url_status == "offline":
                    score = 40

                first_seen: Optional[datetime] = None
                try:
                    first_seen = datetime.strptime(dateadded, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

                last_seen: Optional[datetime] = None
                if last_online:
                    try:
                        last_seen = datetime.strptime(last_online, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        pass

                iocs.append(self._make_ioc(
                    ioc_type="url",
                    value=url,
                    tags=tags,
                    threat_score=score,
                    confidence=70,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    metadata={"status": url_status, "threat": threat, "source": "urlhaus"},
                ))
            except (IndexError, ValueError):
                continue

        return iocs
