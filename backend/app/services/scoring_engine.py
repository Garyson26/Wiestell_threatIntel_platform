"""IOC threat scoring engine.

Calculates a composite threat score (0-100) from six weighted factors: base
reputation, source diversity, recency, sighting frequency, enrichment risk and
context. The weight given to each factor depends on the IOC type — see
:data:`WEIGHT_PROFILES`.

Scoring must be a pure function of *evidence*. It must never read back a value
it previously produced: ``threat_score`` is a computed column, so consuming it
as an input makes the score a function of how many times enrichment has run
rather than of the indicator. That defect was live until 2026-07-28 and drove a
fresh CISA KEV entry from 46 to a fixed point of 53 over successive passes.

The corollary, added 2026-07-29: **an absence of evidence is not evidence.** Two
places used to break that rule, in the same direction, both making unexamined
indicators look safe:

* ``_base_reputation_score`` scored 0.0 when providers were consulted and none
  flagged the indicator. But AbuseIPDB is IP-only, so for a URL or a hash
  "providers were consulted" could mean OTX alone — and a fresh malware URL that
  OTX has never indexed is the *expected* state for a new indicator, not a clean
  bill of health. 0.0 now requires positive evidence: a corroborated harmless
  verdict from a provider that covers the type, and no ``ioc_sources`` row from
  an enabled feed. Every feed here is a malicious-indicator feed, so feed
  presence is itself reputation evidence.
* ``_enrichment_risk_score`` counted a failed or unconfigured source in its
  denominator, so an enricher that errored actively lowered the risk ratio.

With the current provider set (AbuseIPDB, OTX) the 0.0 branch is **unreachable**:
neither provider has a corroborated clean-assertion channel — OTX's
``pulse_count: 0`` is silence, and AbuseIPDB's confidence score is derived from
abuse reports, so zero reports is also silence. Reputation therefore ranges
30-100 in practice. The branch is retained because it documents what evidence
would justify a 0.0 and becomes correct the moment such a provider is added;
``TestZeroReputationIsUnreachable`` fails when that happens, so the change is
noticed rather than assumed.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Mapping, Optional

# ── Weight profiles ───────────────────────────────────────────────────────────
# Keyed on IOC type, with an explicit default. "default" reproduces the original
# global weighting exactly, so non-CVE scores are unaffected by the per-type
# work. Each profile must sum to 1.0 (asserted at import).
WEIGHT_PROFILES: Dict[str, Dict[str, float]] = {
    "default": {
        "reputation": 0.30,
        "diversity": 0.20,
        "recency": 0.15,
        "frequency": 0.15,
        "enrichment": 0.10,
        "context": 0.10,
    },
    # Vulnerabilities are a different kind of object from network indicators.
    # Only two CVE feeds exist (CISA KEV, eCrimeLabs Metasploit), so corroboration
    # cannot move; and "how often have we seen this CVE" is a meaningless question
    # — a feed republishing its catalogue daily is not new evidence. Under the
    # default profile those two terms held 35% of the composite and no fresh
    # actively-exploited CVE could reach "critical" (measured ceiling 66, peaking
    # 20 days *after* publication — urgency inverted).
    #
    # Weight moves to what actually describes a vulnerability's urgency: CVSS
    # severity (via reputation), CISA KEV membership and public exploit
    # availability (via enrichment), and campaign tagging (via context).
    "cve": {
        "reputation": 0.30,   # CVSS v3.1 base score, scaled 0-100
        "diversity": 0.05,    # retained so a second feed still counts for something
        "recency": 0.10,
        "frequency": 0.00,    # sighting count is re-sync noise for a CVE
        "enrichment": 0.30,   # KEV membership + public exploit availability
        "context": 0.25,      # ransomware / APT / exploited-in-the-wild tags
    },
}

_WEIGHT_KEYS = ("reputation", "diversity", "recency", "frequency", "enrichment", "context")

# Neutral reputation used when no reputation evidence of any kind is available.
NEUTRAL_REPUTATION = 30.0


# ── Scoring model version ─────────────────────────────────────────────────────
# Bumped whenever a change alters what score an unchanged indicator receives.
#
# WHY IT EXISTS. Nothing re-scores an existing row automatically any more. Ingestion
# skips rows whose evidence has not changed (feed_ingestion._rescore_reason) and the
# enrichment cron selects only never-enriched IOCs, so a model change reaches the
# corpus solely through scripts/rescore_corpus.py. That script needs to know *which*
# rows are stale, and this constant is how: once `iocs.scoring_model_version` exists
# it targets `WHERE scoring_model_version < SCORING_MODEL_VERSION`.
#
# The column is blocked on the migration-chain repair, so for now the constant lives
# in code only and each change set records which version it represents. That costs
# nothing and avoids a second pass once the column lands.
#
# BUMPING IS AN ACCEPTANCE CRITERION, NOT A JUDGEMENT CALL. The guard below cannot
# catch every score-affecting change — adding an `assessed` contract, or a new
# enricher branch, alters what reaches `total_signals` without necessarily editing any
# function body hashed here. So every change set that touches scoring ends by bumping
# this and saying what it represents.
#
# History:
#   1  pre-2026-07-28 baseline: reputation read back threat_score (feedback loop),
#      source_count was the sighting count, provider silence scored as clean.
#   2  2026-07-29  reputation evidence model; enrichment-risk dilution fix; the
#      VirusTotal provider removed.
#   3  2026-07-31  re-read gate: sighting_count and last_seen from source timestamps;
#      full-list current-state vs cumulative semantics; enrichment_data passed on the
#      re-read path (previously collapsed two terms to their no-evidence defaults).
#   4  2026-07-31  per-signal `assessed` contract: enrichers declare which signals they
#      evaluated and `_enrichment_risk_score` charges the denominator only for those,
#      instead of inferring assessment from key presence. Moves any payload that
#      assessed a *subset* of its source's signals — measured: an NVD entry with a KEV
#      determination but no CVSS v3.1 score goes from 3-of-6 (50.0) to 1-of-1 (100.0),
#      lifting such a CVE by ~15 points of composite, medium -> high. Payloads that
#      assessed everything are unchanged.
#   5  2026-07-31  MIN_ASSESSED_POINTS: the enrichment-risk ratio is taken against at
#      least 3 assessed points, so a proportion computed from less than one source's
#      worth of evidence is smoothed toward neutral instead of saturating. Lowers only
#      payloads that assessed fewer than 3 points; nothing at or above 3 moves. Affects
#      2 of the 21 reachable shapes per non-CVE IOC type, and caps geoip-only and
#      dns-only evidence (source maxima of 2) at 200/3 where they previously read 100.0.
#      Does not touch KEV-without-CVSS, which assesses exactly 3.
#   6  2026-07-31  MalwareBazaar scored for the first time: `family_attribution` (3),
#      `sample_present` (2), `vendor_detections` (1), source maximum 6. Affects hash
#      IOCs only, and only where an abuse.ch key is configured. A confirmed named
#      family goes from contributing nothing to 5/6 of the risk term. `sample_present`
#      exists so a held-but-unattributed sample floors at 2/6 rather than scoring 0
#      against a non-zero denominator — MalwareBazaar's corpus is malware-only, so
#      membership is itself evidence.
#      Also widened the fingerprint's scope in the same change: RISK_SIGNALS,
#      MIN_ASSESSED_POINTS and every `_risk_*` scorer are now hashed. They were not,
#      which is why this branch initially landed without tripping the guard.
#   7  2026-07-31  design B': hash reputation reads MalwareBazaar family attribution
#      (named + vendor 90, named 80, held-unattributed 55) **ahead of** the reputation
#      aggregate, and `family_attribution` moves OUT of RISK_SIGNALS, taking the
#      MalwareBazaar source maximum from 6 to 3. Reputation takes identity, enrichment
#      keeps corroboration — the same split as NVD (CVSS to reputation, KEV/exploit to
#      enrichment), so nothing is counted twice.
#      Affects hash IOCs only, and only where an abuse.ch key is configured. Measured on
#      a sample named AgentTesla with vendor intel and a YARAify hit: 44 -> 62 at one
#      feed and 54 -> 72 at four, medium -> high, under the UNCHANGED `default` profile.
#      That supersedes the version-6 conclusion that a hash weight profile was needed;
#      it was needed only under the rejected design where enrichment carried identity.
#      Ordered ahead of the aggregate because OTX's `aggregate_score` is
#      `pulse_count * 10`, so a single pulse reads 10 and would otherwise override a
#      named-family identification: 36 composite against 60.
#   8  2026-07-31  reputation provider aggregation is MAX, not mean. Providers only
#      enter the list on a positive reading, so a mean measured how loudly they agreed
#      and dragged the strongest verdict toward the weakest. Measured: an IP AbuseIPDB
#      rated 100/100 read aggregate 55 and composite 45 (medium) because OTX had also
#      flagged it once — corroborating evidence LOWERING the score, on the largest IOC
#      population. Under max it reads 100 / 58 (high).
#      Identical whenever only one provider is positive, which is the common case, so
#      only the both-positive-and-disagreeing case moves. Applies to every IOC type.
#      Also recomputed scorer-side from `details` (`_strongest_provider_score`), because
#      `aggregate_score` is a stored field and enrichment rows are never refreshed — so
#      without that, a rescore would faithfully reuse the mean and the fix would never
#      reach the existing corpus. One-sided: it can only raise a stored value.
#      STILL OPEN and deliberately not in this version: the scale mismatch. One OTX
#      pulse maps to 10, below NEUTRAL_REPUTATION, and an AbuseIPDB confidence of 5
#      maps to 5 — so a positive verdict can still read safer than silence. Blocked on
#      the pulse-count distribution; must cover both providers.
#   9  2026-07-31  the §6b max reaches the OTHER consumer of `aggregate_score`.
#      `_risk_reputation_aggregate` — the enrichment-risk scorer for the reputation
#      signal — was still reading the stored value, so on a row written before §6b the
#      reputation term used the corrected max while the risk term used the stale mean:
#      one payload driving two terms from two different numbers. A mean of 55 scored 1
#      point where the correct 100 scores 3. Found by asking whether the field is read
#      anywhere besides the reputation fallback; it is, and neither read is vestigial.
#      Affects legacy rows of every IOC type that carry a reputation payload with
#      `details`. No effect on rows written after §6b, where stored and recomputed agree.
SCORING_MODEL_VERSION = 9

# SHA-256 over the score-determining code, docstrings and formatting excluded. Moves
# together with SCORING_MODEL_VERSION in review; see
# tests/test_scoring_and_export.py::TestScoringModelVersion for the guard and for why
# it fails rather than auto-bumping.
SCORING_MODEL_FINGERPRINT = "a971fb80fcb13a3b6315b2793b21e84d"


def _weights_for(ioc_type: Optional[str]) -> Dict[str, float]:
    """Weight profile for an IOC type, falling back to the default profile."""
    return WEIGHT_PROFILES.get((ioc_type or "").lower(), WEIGHT_PROFILES["default"])


def calculate_threat_score(
    ioc_data: Dict[str, Any],
    source_count: int = 1,
    enrichment_data: Optional[List[Dict]] = None,
    has_enabled_feed_source: Optional[bool] = None,
) -> int:
    """Calculate the composite threat score for an IOC.

    Args:
        ioc_data: indicator fields. ``threat_score`` is deliberately ignored —
            see the module docstring.
        source_count: number of **distinct feeds** that have reported this
            indicator. Not the sighting count.
        enrichment_data: ``[{"source": ..., "data": {...}}, ...]`` as returned by
            the enrichment engine.
        has_enabled_feed_source: whether an ``ioc_sources`` row from an *enabled*
            feed exists. Gates the 0.0 reputation floor only; it never
            contributes additively, and it is deliberately **not** folded into
            ``source_count`` — filtering the distinct-feed count on
            ``feed_sources.is_enabled`` would move the diversity term for every
            indicator a since-disabled feed once reported. ``None`` means the
            caller does not know, and is treated as "yes" so that unknown can
            never resolve to clean.
    """
    enrichment_data = enrichment_data or []
    ioc_type = ioc_data.get("type")
    weights = _weights_for(ioc_type)

    # An analyst-set score wins outright. This is read from a dedicated
    # nullable field, never from `threat_score` — reading back a computed column
    # cannot distinguish a human override from the engine's own last output,
    # which is precisely the bug this replaces.
    #
    # NOTE: `manual_score_override` is not yet a column on `iocs`. Adding it
    # needs owner sign-off, so the hook reads whatever the caller supplies and
    # no migration ships with this change. Until the column exists the key is
    # simply never present.
    override = ioc_data.get("manual_score_override")
    if isinstance(override, (int, float)) and not isinstance(override, bool):
        return max(0, min(100, round(float(override))))

    base_score = _base_reputation_score(
        ioc_data, enrichment_data, has_enabled_feed_source
    )
    diversity_score = _source_diversity_score(source_count)
    recency = _recency_score(ioc_data.get("last_seen"))
    frequency = _sighting_frequency_score(ioc_data.get("sighting_count", 1))
    enrichment = _enrichment_risk_score(enrichment_data)
    context = _context_score(ioc_data.get("tags", []), ioc_data.get("mitre_techniques", []))

    composite = (
        base_score * weights["reputation"]
        + diversity_score * weights["diversity"]
        + recency * weights["recency"]
        + frequency * weights["frequency"]
        + enrichment * weights["enrichment"]
        + context * weights["context"]
    )

    return max(0, min(100, round(composite)))


def _mean_reputation_scores(raw: Any) -> Optional[float]:
    """Mean of a ``reputation_scores`` mapping, or None if unusable.

    Feed metadata is untrusted third-party input and scoring runs inside the
    ingestion path, so a malformed payload must degrade rather than abort the
    chunk. Confirmed crash inputs before this guard: a list (``AttributeError``
    on ``.values()``) and a mapping holding ``None``/``str``/``dict`` values
    (``TypeError`` on ``sum()``).

    The payload is never logged — feed metadata can carry values that redaction
    cannot usefully classify.
    """
    if not isinstance(raw, Mapping):
        return None

    numeric = [
        float(v)
        for v in raw.values()
        # bool is an int subclass; a True/False verdict is not a 0-100 score.
        if isinstance(v, (int, float)) and not isinstance(v, bool)
    ]
    if not numeric:
        return None
    return sum(numeric) / len(numeric)


def _reputation_providers(data: Mapping) -> List[Mapping]:
    """Per-provider records from a reputation payload; ``[]`` for old-shape rows.

    ``providers`` was added when reputation moved to an evidence model. Rows
    cached before that carry only ``aggregate_score`` / ``sources_checked``, so
    this must tolerate their absence.

    **Correction 2026-07-30:** an earlier version of this docstring said such rows
    "expire naturally via ``CACHE_TTL_REPUTATION``". They do not. ``expires_at`` is
    honoured by ``_get_cached_enrichment`` only *once enrichment is triggered for an
    IOC*, and the cron triggers it only for IOCs with **no** enrichment row at all
    (``feeds.py``: ``WHERE Enrichment.id IS NULL``). An IOC enriched once is never
    re-enriched, so its payload never refreshes. Old-shape rows are therefore
    **permanent** until Spec 2 Phase 4 corrects that selection, and this fallback is
    load-bearing rather than transitional.
    """
    raw = data.get("providers")
    if not isinstance(raw, list):
        return []
    return [p for p in raw if isinstance(p, Mapping)]


def _reputation_provider_responded(data: Any) -> bool:
    """True when a provider that *supports this IOC type* returned an answer.

    A provider that does not cover the type was never consulted, so it is not
    evidence of anything. AbuseIPDB is IP-only: for a URL or a hash it must not
    be counted merely because it is configured.

    Old-shape rows fall back to ``sources_checked``, which answers this narrower
    question correctly even though it cannot distinguish harmless from silent.
    """
    if not isinstance(data, Mapping):
        return False
    providers = _reputation_providers(data)
    if providers:
        return any(p.get("supports_type") and p.get("responded") for p in providers)
    return bool(data.get("sources_checked"))


def _reputation_reached_verdict(data: Any) -> bool:
    """True when a reputation payload carries an actual verdict, not just a reply.

    Narrower than :func:`_reputation_provider_responded`, and deliberately so.
    That predicate answers "is ``aggregate_score`` meaningful"; this one answers
    "did reputation produce evidence", which is what the risk ratio needs.

    A provider that answered and was ``silent`` produced no evidence, so it must
    not enter the risk denominator — otherwise silence would be scored as a
    low-risk signal here while being correctly rejected as a clean signal in
    :func:`_base_reputation_score`. The same absence cannot mean two things.

    Old-shape rows fall back to ``sources_checked``: they cannot distinguish
    harmless from silent, so they keep their previous behaviour and expire on the
    cache TTL.
    """
    if not isinstance(data, Mapping):
        return False
    providers = _reputation_providers(data)
    if providers:
        return any(
            p.get("supports_type")
            and p.get("responded")
            and p.get("verdict") in ("malicious", "harmless")
            for p in providers
        )
    return bool(data.get("sources_checked"))


def _is_corroborated_harmless(data: Mapping) -> bool:
    """Positive evidence that an indicator is *not* malicious.

    Requires all of: a provider that supports the type responded; its verdict is
    ``harmless``; that verdict is backed by a non-zero report / sample / analysis
    count; and no provider returned ``malicious``.

    The corroboration requirement is the crux. A provider answering "0 reports,
    never seen" has told us nothing — it is silent, not exculpatory. Without this
    check a brand-new malware URL that no reputation provider has indexed yet
    scores 0.0 on 30% of the composite, penalising precisely the newest and most
    actionable indicators.

    An old-shape payload cannot satisfy this and returns False: missing evidence
    is unknown, never clean.
    """
    providers = _reputation_providers(data)
    if not providers:
        return False

    if any(p.get("verdict") == "malicious" for p in providers):
        return False

    supporting = [p for p in providers if p.get("supports_type") and p.get("responded")]
    if not supporting:
        return False

    for provider in supporting:
        if provider.get("verdict") != "harmless":
            continue
        count = provider.get("corroboration")
        if isinstance(count, (int, float)) and not isinstance(count, bool) and count > 0:
            return True
    return False


def _strongest_provider_score(data: Mapping) -> Optional[float]:
    """Recompute the aggregate as a MAX over per-provider scores in ``details``.

    Why this lives here as well as in the enricher. The enricher now stores a max, but
    ``aggregate_score`` is a *stored* field and enrichment rows are never refreshed on
    the cron path (``WHERE Enrichment.id IS NULL``), so every existing row keeps the
    mean it was written with — permanently, and a rescore would faithfully reuse it.
    Recomputing from ``details``, which is in the same stored JSON, is what makes the
    fix reach the existing corpus when ``scripts/rescore_corpus.py`` runs instead of
    waiting on the freeze trap being fixed.

    Returns ``None`` when no per-provider value can be derived, so the caller falls back
    to the stored ``aggregate_score`` and nothing is invented.

    Mirrors the enricher's "flagged" condition exactly: only a provider with a positive
    reading contributes, because a zero means silence rather than a clean verdict. It
    does **not** rescale — one OTX pulse still reads 10. See §8 item 15.
    """
    details = data.get("details")
    if not isinstance(details, Mapping):
        return None

    candidates: List[float] = []

    abuseipdb = details.get("abuseipdb")
    if isinstance(abuseipdb, Mapping):
        score = abuseipdb.get("score")
        if isinstance(score, (int, float)) and not isinstance(score, bool) and score > 0:
            candidates.append(float(min(100.0, float(score))))

    otx = details.get("otx")
    if isinstance(otx, Mapping):
        pulses = otx.get("pulse_count")
        if isinstance(pulses, (int, float)) and not isinstance(pulses, bool) and pulses > 0:
            candidates.append(float(min(float(pulses) * 10.0, 100.0)))

    return max(candidates) if candidates else None


def normalize_enrichment_for_display(source: str, data: Any) -> Any:
    """Return ``data`` with ``aggregate_score`` corrected, for serialisation to clients.

    The IOC detail pages render ``aggregate_score`` in a reputation table beside the
    threat-score badge. Since the aggregator became a max (§6b) the *stored* value on any
    row written earlier is a mean, so without this an analyst reads 55 next to a badge
    computed from 100 — the UI contradicting the score, and displaying the exact number
    the change decided was wrong.

    Corrects the displayed copy rather than the row: rewriting stored enrichment payloads
    would be a data migration, and this keeps one implementation of the rule instead of a
    second copy in TypeScript. Non-reputation payloads and anything without usable
    ``details`` pass through untouched, and the original dict is never mutated.
    """
    if source != "reputation" or not isinstance(data, Mapping):
        return data
    strongest = _strongest_provider_score(data)
    if strongest is None:
        return data
    stored = data.get("aggregate_score")
    if isinstance(stored, (int, float)) and not isinstance(stored, bool) \
            and float(stored) >= strongest:
        return data
    corrected = dict(data)
    corrected["aggregate_score"] = int(strongest)
    return corrected


def _reputation_from_enrichment(
    enrichment_data: List[Dict],
    has_enabled_feed_source: Optional[bool] = None,
) -> Optional[float]:
    """Aggregate reputation score from the ``reputation`` enrichment payload.

    Two distinct guards, for two distinct failure modes:

    1. ``aggregate_score`` is meaningless unless a provider covering this IOC
       type actually answered — the enricher reports 0 both for "checked and
       clean" and for "nothing was configured".
    2. A score of **0.0 is a strong claim** and needs positive evidence behind
       it. See :func:`_is_corroborated_harmless` and the feed-source floor below.

    Everything that fails either guard returns ``None``, which the caller reads
    as *unknown* and resolves to :data:`NEUTRAL_REPUTATION`.
    """
    for entry in enrichment_data:
        if entry.get("source") != "reputation":
            continue
        data = entry.get("data") or {}
        if not isinstance(data, Mapping):
            continue
        if not _reputation_provider_responded(data):
            return None
        score = data.get("aggregate_score")
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            return None
        score = float(max(0.0, min(100.0, float(score))))

        # Prefer a max recomputed from the per-provider detail, which corrects rows
        # written when this was a mean without waiting for them to be re-enriched.
        # Never *lowers* the stored value: max over the same providers is >= their mean.
        strongest = _strongest_provider_score(data)
        if strongest is not None:
            score = max(score, strongest)

        if score == 0.0:
            # Presence in any curated feed is itself reputation evidence: all
            # eleven feeds in this platform are malicious-indicator feeds and
            # none are allowlists, so URLhaus listing a URL is a positive
            # assertion that it is malicious. Scoring it 0.0 because a different
            # provider is silent inverts the signal.
            #
            # `None` means the caller could not tell us, and unknown must never
            # resolve to clean — so only an explicit `False` opens this door.
            if has_enabled_feed_source is not False:
                return None
            if not _is_corroborated_harmless(data):
                return None
        return score
    return None


def _reputation_from_cvss(enrichment_data: List[Dict]) -> Optional[float]:
    """CVSS v3.1 base score from NVD enrichment, scaled 0.0-10.0 to 0-100.

    For a vulnerability, severity *is* the reputation signal — there is no
    blocklist consensus to draw on.
    """
    for entry in enrichment_data:
        if entry.get("source") != "nvd":
            continue
        data = entry.get("data") or {}
        if not isinstance(data, Mapping):
            continue
        cvss = data.get("nvd_cvss_v31_score")
        if isinstance(cvss, (int, float)) and not isinstance(cvss, bool):
            return float(max(0.0, min(100.0, float(cvss) * 10.0)))
    return None


# MalwareBazaar `signature` values meaning "held, but no family assigned".
_UNATTRIBUTED = {"", "unknown", "n/a", "none", "null", "unattributed"}

# Reputation for a hash MalwareBazaar holds. Membership alone is evidence — the corpus
# is malware-only — and a named family is the strongest identification available.
_MB_NAMED_CORROBORATED = 90.0
_MB_NAMED = 80.0
_MB_HELD_UNATTRIBUTED = 55.0


def _reputation_from_malwarebazaar(enrichment_data: List[Dict]) -> Optional[float]:
    """Family attribution as the reputation term, for hashes only.

    Mirrors :func:`_reputation_from_cvss`. For a vulnerability, severity *is* the
    reputation signal because there is no blocklist consensus to draw on; for a file
    hash, **identity** is — "this sample is AgentTesla" is a stronger statement about
    the indicator than any pulse count.

    This is the split that keeps the signal from landing twice. Reputation takes
    *identity* (``signature``); enrichment risk keeps *corroboration*
    (``sample_present``, ``vendor_detections``). Exactly as NVD splits: CVSS severity to
    reputation, KEV membership and exploit availability to enrichment. So
    ``family_attribution`` **moved** out of :data:`RISK_SIGNALS` rather than being
    de-weighted inside it.

    Returns ``None`` when MalwareBazaar does not hold the sample, so resolution falls
    through to the reputation aggregate as before.

    **Consulted ahead of the reputation aggregate**, unlike the CVSS path. Measured
    2026-07-31: OTX's ``aggregate_score`` is ``pulse_count * 10``, so a single pulse
    yields 10 — and a thin OTX verdict would otherwise override MalwareBazaar naming the
    family, taking a confirmed sample from 60 composite to 36. See PROJECT_SUMMARY.md §8
    item 15 for the underlying scale defect, which this ordering sidesteps for hashes but
    does not fix for IPs.
    """
    for entry in enrichment_data:
        if entry.get("source") != "malwarebazaar":
            continue
        data = entry.get("data") or {}
        if not isinstance(data, Mapping) or not data.get("found"):
            continue
        signature = data.get("signature")
        named = (
            isinstance(signature, str)
            and signature.strip().lower() not in _UNATTRIBUTED
        )
        if not named:
            # Held but unattributed. Still malicious — it is in a malware corpus — so
            # this must stay above NEUTRAL_REPUTATION, not fall through to it.
            return _MB_HELD_UNATTRIBUTED
        return (
            _MB_NAMED_CORROBORATED if data.get("vendor_intel") else _MB_NAMED
        )
    return None


def _base_reputation_score(
    ioc_data: Dict[str, Any],
    enrichment_data: Optional[List[Dict]] = None,
    has_enabled_feed_source: Optional[bool] = None,
) -> float:
    """Reputation component (0-100), derived only from external evidence.

    Resolution order:
      1. ``metadata.reputation_scores`` — a per-provider mapping written by a
         feed connector. Note that no connector populates this today; it is
         retained as the documented extension point.
      2. **for hashes**, MalwareBazaar family attribution — see
         :func:`_reputation_from_malwarebazaar` for why this precedes the aggregate.
      3. the ``reputation`` enrichment payload's ``aggregate_score``
         (AbuseIPDB / OTX), when a provider covering this IOC type responded.
      4. for CVEs, the NVD CVSS v3.1 base score scaled to 0-100.
      5. a neutral constant.

    A score of 0.0 requires positive evidence of harmlessness at step 3; every
    other absence resolves to the neutral constant. In practice that makes 0.0
    unreachable with the current provider set — see the module docstring.

    **Why the hash path is at step 2 and the CVE path at step 4.** They are not
    symmetric, deliberately. NVD and the reputation providers answer different
    questions and rarely both respond for a CVE, so CVSS is a genuine fallback. For a
    hash, MalwareBazaar and OTX both answer, and OTX answers *worse*: its
    ``aggregate_score`` is ``pulse_count * 10``, so one pulse reads 10 — below the
    no-evidence neutral. Leaving MalwareBazaar as a fallback would let a single OTX
    mention override a named-family identification. Measured: 36 composite against 60.

    This function must not consult ``ioc_data["threat_score"]``.
    """
    enrichment_data = enrichment_data or []
    metadata = ioc_data.get("metadata") or {}
    ioc_type = (ioc_data.get("type") or "").lower()

    if isinstance(metadata, Mapping) and "reputation_scores" in metadata:
        mean = _mean_reputation_scores(metadata["reputation_scores"])
        if mean is not None:
            return mean

    if ioc_type == "hash":
        from_malwarebazaar = _reputation_from_malwarebazaar(enrichment_data)
        if from_malwarebazaar is not None:
            return from_malwarebazaar

    from_enrichment = _reputation_from_enrichment(
        enrichment_data, has_enabled_feed_source
    )
    if from_enrichment is not None:
        return from_enrichment

    if ioc_type == "cve":
        from_cvss = _reputation_from_cvss(enrichment_data)
        if from_cvss is not None:
            return from_cvss

    return NEUTRAL_REPUTATION


def _source_diversity_score(source_count: int) -> float:
    """Corroboration across independent feeds.

    A step function on the **absolute number of distinct feeds** reporting the
    indicator, with a floor of 30 for a single source. It is deliberately not
    proportional to the size of the feed catalogue: making it proportional would
    move every score already in the database.

    ``source_count`` must be a count of distinct feeds. Passing the sighting
    count — as the ingestion path did until this change — makes a single feed
    re-syncing five times look like five independent corroborating sources.
    """
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


# ── Per-signal assessment registry ───────────────────────────────────────────
# The enrichment-risk term is ``risk_signals / total_signals``, so every signal that
# enters the denominator without entering the numerator pushes the score down. Which
# signals were actually *assessed* is therefore the load-bearing question, and only
# the enricher can answer it.
#
# WHY THIS EXISTS. Four instances of the same bug were found by reading enrichers, none
# by reading this module, all in the same direction — an absence read as reassurance:
#
#   1. reputation      "providers consulted, none flagged" scored as confirmed-clean,
#                      when AbuseIPDB is IP-only so for a URL it meant OTX alone.
#   2. reverse DNS     carries no `fast_flux` key at all, so every IP with a PTR row
#                      charged 2 denominator points against 0 risk.
#   3. forward DNS     builds `records` with all five rtypes pre-populated to [], so
#                      an NXDOMAIN domain is a *truthy dict of empty lists* and looked
#                      identical to "resolved, few A records".
#   4. GeoIP           writes `error_city`, not `error`, when the MaxMind database is
#                      missing — so the generic error check missed it entirely.
#
# The common cause is this module inferring "did we assess this" from key presence.
# Key presence cannot express it: a key can be absent because the source said nothing,
# or present-but-empty because the source said "nothing found", and those are opposite
# answers.
#
# So the enricher declares it. ``enrich()`` returns ``assessed``, a list of signal
# names it actually evaluated, and this module adds to ``total_signals`` only for names
# in that list. It still reads keys for each signal's *value* — just never to decide
# whether the signal was assessed.
#
# PER SIGNAL, not per source, because a source can reach a verdict on one signal and
# not another. Measured case: an NVD payload with a KEV determination but no CVSS
# charged all six denominator points for three assessable points, giving 50.0 where
# 100.0 is correct — about 15 points of composite under the ``cve`` profile.
#
# Signal names here MUST match what the enrichers declare;
# ``tests/test_enrichers.py::TestAssessedContract`` asserts both directions so a rename
# breaks loudly rather than silently zeroing a term.

def _risk_high_risk_country(data: Mapping) -> int:
    return 2 if data.get("country_code") in {"RU", "CN", "KP", "IR"} else 0


def _risk_privacy_protected(data: Mapping) -> int:
    return 1 if data.get("privacy_protected") else 0


def _risk_domain_age(data: Mapping) -> int:
    """Young domains are higher risk. Under 30 days scores; older does not."""
    created = data.get("creation_date")
    if not created:
        return 0
    try:
        parsed = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return 2 if (datetime.now(timezone.utc) - parsed).days < 30 else 0


def _risk_fast_flux(data: Mapping) -> int:
    return 2 if data.get("fast_flux") else 0


def _risk_reputation_aggregate(data: Mapping) -> int:
    """Reputation as an enrichment-risk signal.

    Reads through :func:`_strongest_provider_score` for the same reason
    :func:`_reputation_from_enrichment` does: ``aggregate_score`` is a stored field
    written under whichever aggregator was live at the time, and rows are never
    refreshed. This is the **second** consumer of that field — missing it in the
    2026-07-31 §6b change left the risk term reading a stale mean while the reputation
    term read the corrected max, so one payload drove two terms with two different
    numbers. A legacy mean of 55 scores 1 point here where the correct 100 scores 3.
    """
    score = data.get("aggregate_score", 0)
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        score = 0
    strongest = _strongest_provider_score(data)
    if strongest is not None:
        score = max(float(score), strongest)
    if score > 70:
        return 3
    if score > 40:
        return 1
    return 0


def _risk_cvss(data: Mapping) -> int:
    cvss = data.get("nvd_cvss_v31_score")
    if not isinstance(cvss, (int, float)) or isinstance(cvss, bool):
        return 0
    if cvss >= 9.0:
        return 3
    if cvss >= 7.0:
        return 2
    if cvss >= 4.0:
        return 1
    return 0


def _risk_kev_membership(data: Mapping) -> int:
    return 3 if data.get("nvd_in_kev") else 0


def _risk_exploit_available(data: Mapping) -> int:
    return 3 if data.get("cvedetails_exploit_available") else 0


def _risk_exploit_references(data: Mapping) -> int:
    return 1 if data.get("cvedetails_exploit_references") else 0


def _risk_sample_present(data: Mapping) -> int:
    """MalwareBazaar's corpus is malware-only, so membership is itself evidence.

    Always positive when a record was returned. That looks degenerate but is the point:
    without it, a held-but-unattributed sample would score 0 risk against a non-zero
    denominator and read *lower* than a hash nobody has ever checked — the same
    absence-as-evidence inversion recorded in the module docstring, in a new place.
    """
    return 2 if data.get("found") else 0


def _risk_vendor_detections(data: Mapping) -> int:
    """Independent corroboration from third-party sandboxes and AV engines."""
    return 1 if data.get("vendor_intel") else 0


def _risk_yara_rules(data: Mapping) -> int:
    return 2 if data.get("yaraify_yara_rules") else 0


def _risk_clamav(data: Mapping) -> int:
    return 1 if data.get("yaraify_clamav") else 0


def _risk_malware_families(data: Mapping) -> int:
    return 1 if data.get("yaraify_malware_families") else 0


# Minimum denominator for the enrichment-risk ratio, in points.
#
# WHY. Every scorer returns either its own full weight or zero, so a signal that is the
# *sole* assessed evidence always yields 1.0 — its weight over its weight. With
# `privacy_protected` at 1 point that means a privacy-shielded domain whose companion
# source assessed nothing reads maximum enrichment risk off a single weak observation.
# A proportion computed from less than one source's worth of evidence is not a
# confidence measure, so the floor supplies the missing evidence as neutral. It is
# additive smoothing in crude form, and crude is right here precisely because it moves
# nothing above the threshold.
#
# 3 IS A JUDGEMENT, NOT A DERIVATION. It is anchored on "one source fully assessed":
# whois's source maximum is 3 and reputation's single signal is 3. But source maxima
# range from 2 (geoip, dns) to 6 (nvd), so the anchor is reasonable rather than forced,
# and no arithmetic picks 3 out of that range. Revisit in Spec 5 §6 once the full
# assessed-points distribution across the corpus is visible.
#
# MEASURED BLAST RADIUS (2026-07-31, exhaustive enumeration of the reachable shape
# space for the registered enrichers): 2 of 21 shapes per IOC type change, and both are
# exactly the cases whose entire evidence is one 1-point signal —
#   whois-absent + fast-flux                100.0 -> 66.7
#   privacy-only + companion assessed none  100.0 -> 33.3
# The three *correct* saturations (everything assessed came back positive) are
# preserved, as is KEV-without-CVSS at 3 assessed points. The rejected alternative —
# charging each source's full maximum once it assesses anything — reintroduces
# dilution: it drops privacy + fast-flux to 60.0 by charging whois for a creation date
# it never received.
MIN_ASSESSED_POINTS = 3

# (source, signal) -> (points it contributes to total_signals, how risk is scored).
# The point weights reproduce the pre-2026-07-31 per-source totals exactly, split out
# per signal: whois 1+2=3, nvd 3+3=6, cvedetails 3+1=4, yaraify 2+1+1=4.
RISK_SIGNALS: Dict[str, Dict[str, Any]] = {
    "geoip": {
        "high_risk_country": (2, _risk_high_risk_country),
    },
    "whois": {
        "privacy_protected": (1, _risk_privacy_protected),
        "domain_age": (2, _risk_domain_age),
    },
    "dns": {
        "fast_flux": (2, _risk_fast_flux),
    },
    "reputation": {
        "aggregate_score": (3, _risk_reputation_aggregate),
    },
    "nvd": {
        "cvss": (3, _risk_cvss),
        "kev_membership": (3, _risk_kev_membership),
    },
    "cvedetails": {
        "exploit_available": (3, _risk_exploit_available),
        "exploit_references": (1, _risk_exploit_references),
    },
    # Added 2026-07-31 (Spec 5 §2); `family_attribution` MOVED OUT the same day
    # (Spec 5 §6, design B'). Reputation now takes identity via
    # `_reputation_from_malwarebazaar`; enrichment risk keeps corroboration only. Source
    # maximum is therefore 3, not 6 — the same split as NVD, where CVSS severity is
    # reputation and KEV/exploit are enrichment, so no signal lands in both terms.
    "malwarebazaar": {
        "sample_present": (2, _risk_sample_present),
        "vendor_detections": (1, _risk_vendor_detections),
    },
    "yaraify": {
        "yara_rules": (2, _risk_yara_rules),
        "clamav": (1, _risk_clamav),
        "malware_families": (1, _risk_malware_families),
    },
}


def _legacy_assessed(source: str, data: Mapping) -> List[str]:
    """Which signals a payload WITHOUT ``assessed`` should be treated as covering.

    **Permanent, not transitional.** This was to be removed once cached rows had
    rolled over, but they never do: ``api/feeds.py``'s enrichment selection is
    ``WHERE Enrichment.id IS NULL``, so an IOC with any enrichment row — however stale
    — is never re-enriched and ``expires_at`` never triggers a refetch on the cron
    path. Legacy payloads therefore persist until Spec 2 Phase 4 fixes that selection
    *and* a full refresh cycle has completed.

    The inference below is the (now-correct) key-presence logic that
    ``_reached_a_verdict`` used, kept so scores do not step-change when ``assessed``
    lands. It is deliberately conservative: where it cannot tell, it assesses nothing,
    because a signal wrongly counted in the denominator lowers the score.
    """
    if not isinstance(data, Mapping):
        return []
    # Any error marker means the source failed. Prefix-matched because geoip writes
    # `error_city` rather than `error` — see the module docstring. This inference-from-
    # naming is exactly what `assessed` replaces, and it survives only for legacy rows.
    if any(str(k) == "error" or str(k).startswith("error_") for k in data):
        return []
    if data.get("found") is False:
        return []

    if source == "geoip":
        return ["high_risk_country"] if data.get("country_code") else []
    if source == "whois":
        landed = any(
            data.get(k) for k in ("privacy_protected", "creation_date", "registrar",
                                  "registrant", "name_servers", "expiration_date")
        )
        if not landed:
            return []
        # `domain_age` is only assessable when a creation date came back.
        return ["privacy_protected"] + (["domain_age"] if data.get("creation_date") else [])
    if source == "dns":
        records = data.get("records")
        if not isinstance(records, Mapping):
            return []
        resolved = any(records.get(r) for r in ("A", "AAAA", "MX", "NS", "TXT"))
        return ["fast_flux"] if resolved else []
    if source == "reputation":
        return ["aggregate_score"] if _reputation_reached_verdict(data) else []
    if source == "nvd":
        out = []
        cvss = data.get("nvd_cvss_v31_score")
        if isinstance(cvss, (int, float)) and not isinstance(cvss, bool):
            out.append("cvss")
        if data.get("nvd_in_kev") is not None:
            out.append("kev_membership")
        return out
    if source == "malwarebazaar":
        # `found` is checked above, so reaching here means a sample record came back.
        # Cached rows predate Spec 5 §2 and carry no `assessed`; they are common,
        # because these rows are never refreshed (see this function's docstring).
        return ["sample_present", "vendor_detections"]
    if source == "cvedetails":
        return ["exploit_available", "exploit_references"]
    if source == "yaraify":
        return ["yara_rules", "clamav", "malware_families"]
    return []


def _assessed_signals(source: str, entry: Mapping, data: Any) -> List[str]:
    """Signal names this payload actually assessed.

    Prefers the enricher's own ``assessed`` declaration and falls back to
    :func:`_legacy_assessed` for cached rows written before the contract existed.
    Unknown names are dropped rather than trusted, so a typo in an enricher cannot
    inflate the denominator with a signal nothing scores.
    """
    if not isinstance(data, Mapping):
        return []

    known = RISK_SIGNALS.get(source, {})
    declared = entry.get("assessed")
    if declared is None and isinstance(data, Mapping):
        # Some enrichers nest their payload, so accept it in either place.
        declared = data.get("assessed")

    if declared is None:
        return _legacy_assessed(source, data)
    if not isinstance(declared, (list, tuple, set)):
        return []
    return [name for name in declared if name in known]


def _enrichment_risk_score(enrichment_data: List[Dict]) -> float:
    """Enrichment-risk component (0-100): assessed risk over assessable risk.

    Only signals the enricher declares as assessed enter either term. See
    :data:`RISK_SIGNALS` for why that is a declaration rather than an inference.
    """
    if not enrichment_data:
        return 20.0

    risk_signals = 0
    total_signals = 0

    for entry in enrichment_data:
        if not isinstance(entry, Mapping):
            continue
        source = entry.get("source", "")
        data = entry.get("data", {})
        registry = RISK_SIGNALS.get(source)
        if not registry:
            # No branch for this source, so it contributes to neither term.
            # MalwareBazaar and Shodan are here: MalwareBazaar confirming a hash as a
            # named family is arguably the strongest single signal this platform holds
            # and is currently unscored — Spec 5 §2.
            continue

        for name in _assessed_signals(source, entry, data):
            points, scorer = registry[name]
            total_signals += points
            try:
                risk_signals += scorer(data)
            except Exception:  # pragma: no cover - a scorer must never break ingestion
                pass

    # ── Zero evidence, BEFORE the floor ──────────────────────────────────────
    # Order is load-bearing. This is "nothing was assessed at all", which is the
    # neutral case, and it must resolve before MIN_ASSESSED_POINTS is applied.
    # Folding the floor in as `total = max(total_signals, MIN_ASSESSED_POINTS)` at
    # the top of the function instead would turn this branch into 0/3 -> 0.0 and
    # drop roughly 2 composite points across the entire never-enriched population
    # — vastly more IOCs than the thin-evidence population the floor exists to fix.
    # Pinned by TestMinimumAssessedEvidence::test_no_evidence_is_neutral_not_zero.
    if total_signals == 0:
        return 20.0

    # ── Additive smoothing: a proportion needs a minimum of evidence ─────────
    # One-sided by construction: `max()` can only ever raise a denominator that is
    # below the floor, so a well-evidenced payload is untouched. That is what
    # separates this from the dilution defect recorded in the module docstring —
    # dilution charged for unassessed capacity *proportionally to how many sources
    # were registered but silent*, so it hit well-evidenced payloads hardest and
    # got worse as enrichers were added. This cannot do either.
    denominator = max(total_signals, MIN_ASSESSED_POINTS)
    return min(100.0, (risk_signals / denominator) * 100)


def _context_score(tags: List[str], mitre_techniques: List[str]) -> float:
    """Score based on contextual information."""
    score = 0.0

    # "cisa-kev" and "exploitable"/"metasploit" mark indicators that are being
    # exploited in the wild or have a public exploit module — treated as high
    # risk alongside APT/ransomware tagging.
    high_risk_tags = {
        "apt", "ransomware", "c2", "c&c", "botnet", "exploit", "zero-day",
        "cisa-kev", "kev", "exploitable", "metasploit",
    }
    medium_risk_tags = {
        "malware", "phishing", "trojan", "backdoor", "dropper", "government-ir",
    }
    
    tag_set = {t.lower() for t in tags}

    if tag_set & high_risk_tags:
        score += 50.0
    if tag_set & medium_risk_tags:
        score += 30.0

    if mitre_techniques:
        score += min(50.0, len(mitre_techniques) * 10.0)

    return min(100.0, score)


def get_score_category(score: int) -> str:
    """Return score category label.

    These boundaries are a published contract: the frontend score badges and
    :func:`get_score_color` both assume 76 / 51 / 26. Adjust the weights in
    :data:`WEIGHT_PROFILES` to change how indicators score — never these
    thresholds.
    """
    if score >= 76:
        return "critical"
    elif score >= 51:
        return "high"
    elif score >= 26:
        return "medium"
    else:
        return "low"


def get_score_color(score: int) -> str:
    """Return hex color for a score value. Boundaries mirror get_score_category."""
    if score >= 76:
        return "#ef4444"
    elif score >= 51:
        return "#f59e0b"
    elif score >= 26:
        return "#eab308"
    else:
        return "#10b981"


def _validate_weight_profiles() -> None:
    """Fail at import if any profile is malformed or does not sum to 1.0."""
    for name, profile in WEIGHT_PROFILES.items():
        missing = set(_WEIGHT_KEYS) - set(profile)
        extra = set(profile) - set(_WEIGHT_KEYS)
        if missing or extra:
            raise ValueError(
                f"weight profile {name!r} key mismatch: missing={sorted(missing)} "
                f"unexpected={sorted(extra)}"
            )
        total = sum(profile.values())
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"weight profile {name!r} sums to {total}, expected 1.0")


_validate_weight_profiles()
