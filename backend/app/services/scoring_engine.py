"""IOC threat scoring engine.

Calculates a composite threat score (0-100) based on multiple factors:
- Base reputation from feeds (30%)
- Source diversity (20%) 
- Recency (15%)
- Sighting frequency (15%)
- Enrichment risk indicators (10%)
- Context from tags/MITRE mapping (10%)
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional


def calculate_threat_score(
    ioc_data: Dict[str, Any],
    source_count: int = 1,
    total_feeds: int = 10,
    enrichment_data: Optional[List[Dict]] = None,
) -> int:
    """Calculate composite threat score for an IOC."""
    
    base_score = _base_reputation_score(ioc_data)
    diversity_score = _source_diversity_score(source_count, total_feeds)
    recency = _recency_score(ioc_data.get("last_seen"))
    frequency = _sighting_frequency_score(ioc_data.get("sighting_count", 1))
    enrichment = _enrichment_risk_score(enrichment_data or [])
    context = _context_score(ioc_data.get("tags", []), ioc_data.get("mitre_techniques", []))

    composite = (
        base_score * 0.30
        + diversity_score * 0.20
        + recency * 0.15
        + frequency * 0.15
        + enrichment * 0.10
        + context * 0.10
    )

    return max(0, min(100, round(composite)))


def _base_reputation_score(ioc_data: Dict[str, Any]) -> float:
    """Score from feed reputation data (0-100)."""
    metadata = ioc_data.get("metadata", {}) or {}
    
    if "reputation_scores" in metadata:
        scores = metadata["reputation_scores"]
        if scores:
            return sum(scores.values()) / len(scores)
    
    existing_score = ioc_data.get("threat_score", 0)
    if existing_score > 0:
        return float(existing_score)
    
    return 30.0


def _source_diversity_score(source_count: int, total_feeds: int) -> float:
    """More independent sources reporting = higher threat score."""
    if total_feeds == 0:
        return 0.0
    ratio = source_count / max(total_feeds, 1)
    if source_count >= 5:
        return 100.0
    elif source_count >= 3:
        return 80.0
    elif source_count >= 2:
        return 60.0
    else:
        return 30.0


def _recency_score(last_seen: Optional[datetime]) -> float:
    """Recently observed IOCs score higher."""
    if last_seen is None:
        return 20.0

    if isinstance(last_seen, str):
        try:
            last_seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return 20.0

    now = datetime.now(timezone.utc)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)

    age = now - last_seen
    
    if age < timedelta(hours=1):
        return 100.0
    elif age < timedelta(hours=24):
        return 85.0
    elif age < timedelta(days=7):
        return 65.0
    elif age < timedelta(days=30):
        return 40.0
    elif age < timedelta(days=90):
        return 20.0
    else:
        return 5.0


def _sighting_frequency_score(sighting_count: int) -> float:
    """More sightings = higher confidence in the threat."""
    if sighting_count >= 100:
        return 100.0
    elif sighting_count >= 50:
        return 85.0
    elif sighting_count >= 20:
        return 70.0
    elif sighting_count >= 10:
        return 55.0
    elif sighting_count >= 5:
        return 40.0
    elif sighting_count >= 2:
        return 25.0
    else:
        return 10.0


def _enrichment_risk_score(enrichment_data: List[Dict]) -> float:
    """Score based on risk indicators from enrichment."""
    if not enrichment_data:
        return 20.0

    risk_signals = 0
    total_signals = 0

    for enrichment in enrichment_data:
        source = enrichment.get("source", "")
        data = enrichment.get("data", {})

        if source == "geoip":
            country = data.get("country_code", "")
            high_risk_countries = {"RU", "CN", "KP", "IR"}
            if country in high_risk_countries:
                risk_signals += 2
            total_signals += 2

        elif source == "whois":
            if data.get("privacy_protected"):
                risk_signals += 1
            creation_date = data.get("creation_date")
            if creation_date:
                try:
                    created = datetime.fromisoformat(str(creation_date).replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - created).days < 30:
                        risk_signals += 2
                except (ValueError, TypeError):
                    pass
            total_signals += 3

        elif source == "dns":
            if data.get("fast_flux"):
                risk_signals += 2
            total_signals += 2

        elif source == "reputation":
            score = data.get("aggregate_score", 0)
            if score > 70:
                risk_signals += 3
            elif score > 40:
                risk_signals += 1
            total_signals += 3

    if total_signals == 0:
        return 20.0

    return min(100.0, (risk_signals / total_signals) * 100)


def _context_score(tags: List[str], mitre_techniques: List[str]) -> float:
    """Score based on contextual information."""
    score = 0.0

    high_risk_tags = {"apt", "ransomware", "c2", "c&c", "botnet", "exploit", "zero-day"}
    medium_risk_tags = {"malware", "phishing", "trojan", "backdoor", "dropper"}
    
    tag_set = {t.lower() for t in tags}

    if tag_set & high_risk_tags:
        score += 50.0
    if tag_set & medium_risk_tags:
        score += 30.0

    if mitre_techniques:
        score += min(50.0, len(mitre_techniques) * 10.0)

    return min(100.0, score)


def get_score_category(score: int) -> str:
    """Return score category label."""
    if score >= 76:
        return "critical"
    elif score >= 51:
        return "high"
    elif score >= 26:
        return "medium"
    else:
        return "low"


def get_score_color(score: int) -> str:
    """Return hex color for a score value."""
    if score >= 76:
        return "#ef4444"
    elif score >= 51:
        return "#f59e0b"
    elif score >= 26:
        return "#eab308"
    else:
        return "#10b981"
