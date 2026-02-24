'use client';

import { useState, useRef, useEffect } from 'react';
import { Send, Sparkles, Bot, User, Loader2, Trash2 } from 'lucide-react';
import { chatWithAI } from '@/lib/api';
import { cn } from '@/lib/utils';
import type { AIChatMessage } from '@/lib/types';

const quickPrompts = [
  { label: "Today's Threats", prompt: 'Summarize the most common cyber threats seen today and provide actionable advice for SOC analysts.' },
  { label: 'Top Critical IOCs', prompt: 'What are the most dangerous types of IOCs a SOC team should prioritize, and how should they be triaged?' },
  { label: 'Threat Landscape', prompt: 'Provide an overview of the current cyber threat landscape including active threat actors, common TTPs, and emerging attack vectors.' },
  { label: 'Incident Response', prompt: 'Walk me through the key steps of incident response when a critical IOC is detected in our environment.' },
];

// Built-in FAQ responses for offline/fallback mode
const faqResponses: Record<string, string> = {
  'what are iocs': `Indicators of Compromise (IOCs) are pieces of forensic data that identify potentially malicious activity on a system or network. Common types include:

- IP Addresses — Malicious IPs associated with C2 servers, botnets, or scanners
- Domains — Known malicious domains used for phishing, malware delivery, or C2
- File Hashes (MD5/SHA256) — Fingerprints of known malware samples
- URLs — Specific malicious URLs hosting exploits or phishing pages
- Email Addresses — Addresses tied to phishing campaigns or threat actors
- CVEs — Known software vulnerabilities being actively exploited

IOCs are the foundation of threat intelligence and are used to detect, block, and investigate threats across your environment.`,

  'what is threat intelligence': `Threat Intelligence (TI) is evidence-based knowledge about existing or emerging threats to an organization's assets. It includes:

- Strategic TI — High-level trends for executives (who is attacking, why)
- Tactical TI — TTPs (Tactics, Techniques & Procedures) used by threat actors
- Operational TI — Details about specific campaigns and attack timelines
- Technical TI — IOCs like IPs, hashes, and domains for automated detection

SENTINEL aggregates technical threat intelligence from multiple feeds, enriches IOCs with contextual data, and provides scoring to help analysts prioritize threats effectively.`,

  'how does sentinel work': `SENTINEL is a Threat Intelligence Platform (TIP) that operates in several stages:

1. INGESTION — Collects IOCs from multiple threat feeds (OTX, AbuseIPDB, PhishTank, etc.)
2. ENRICHMENT — Enriches IOCs with WHOIS, DNS, GeoIP, and reputation data
3. SCORING — Assigns threat scores (0-100) based on multiple factors
4. CORRELATION — Links related IOCs and maps to MITRE ATT&CK techniques
5. REPORTING — Generates daily briefs, custom reports, and AI-powered analysis

Key features:
- Real-time feed synchronization with configurable intervals
- Multi-source enrichment for comprehensive context
- MITRE ATT&CK mapping for TTP tracking
- AI-powered analysis and chat assistance (Groq / Llama 3.3)
- Interactive dashboard with geo-mapping and trend analysis`,

  'what is mitre attack': `MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-recognized knowledge base of adversary behavior. It categorizes attacks into:

TACTICS (the "why"):
- Reconnaissance, Resource Development, Initial Access
- Execution, Persistence, Privilege Escalation
- Defense Evasion, Credential Access, Discovery
- Lateral Movement, Collection, C2, Exfiltration, Impact

TECHNIQUES (the "how"):
Each tactic contains specific techniques (e.g., T1566 Phishing under Initial Access).

In SENTINEL, IOCs are mapped to ATT&CK techniques to help analysts understand:
- What stage of an attack an IOC relates to
- What TTPs a threat actor is using
- Where to focus defensive efforts

Use the ATT&CK Map page to visualize technique coverage across your IOC data.`,

  'how to investigate an ioc': `Step-by-step IOC investigation workflow in SENTINEL:

1. IDENTIFY — Find the IOC via search or alert triage
2. ENRICH — Click "Enrich" to pull WHOIS, DNS, GeoIP, and reputation data
3. SCORE — Review the threat score (0-25 Low, 26-50 Medium, 51-75 High, 76-100 Critical)
4. CORRELATE — Check the Relationships tab for linked IOCs
5. CONTEXTUALIZE — Review sources, tags, and MITRE ATT&CK mappings
6. AI ANALYSIS — Use the AI Analysis tab for automated threat assessment
7. DECIDE — Based on findings, take action:
   - Block: Add to firewall/proxy blocklist
   - Monitor: Set up alerts for future sightings
   - Escalate: Create a report for the SOC team
   - Dismiss: Mark as false positive if benign

Pro tips:
- Check sighting count and first/last seen dates for recency
- Cross-reference multiple enrichment sources
- Look for related IOCs that may indicate a broader campaign`,

  'what are threat feeds': `Threat feeds are continuous streams of IOC data from various sources. SENTINEL supports multiple feed types:

PUBLIC FEEDS (Free):
- AlienVault OTX — Community-driven threat data
- Abuse.ch — Malware and botnet tracking (URLhaus, MalwareBazaar)
- PhishTank — Community-verified phishing URLs
- Emerging Threats — Snort/Suricata rule-based IOCs

COMMERCIAL FEEDS (API key required):
- VirusTotal — Multi-engine malware scanning
- AbuseIPDB — IP reputation database
- Shodan — Internet-connected device intelligence

CUSTOM FEEDS:
- CSV/STIX imports for internal or third-party data

Feeds sync automatically at configurable intervals. Check the Threat Feeds page to manage sources, trigger manual syncs, and monitor feed health.`,

  'explain threat scoring': `SENTINEL uses a 0-100 threat scoring system:

SCORE RANGES:
- 0-25   LOW      — Minimal risk, likely benign or low-confidence
- 26-50  MEDIUM   — Moderate risk, warrants monitoring
- 51-75  HIGH     — Significant risk, should be investigated
- 76-100 CRITICAL — Severe risk, immediate action recommended

SCORING FACTORS:
- Source reputation: Higher-confidence feeds increase the score
- Sighting count: Multiple independent sightings boost severity
- Recency: Recently active IOCs score higher
- Enrichment data: Reputation checks (AbuseIPDB, VT) contribute
- Context: Associated malware families or APT groups

WHAT TO DO:
- Critical (76+): Immediate blocking + incident investigation
- High (51-75): Priority investigation within 4 hours
- Medium (26-50): Investigate within 24 hours
- Low (0-25): Monitor, review during routine analysis`,

  'incident response steps': `Key Incident Response steps when a critical IOC triggers an alert:

1. DETECTION & TRIAGE
   - Verify the alert is not a false positive
   - Check the IOC's threat score, sources, and enrichment data
   - Determine affected systems and scope

2. CONTAINMENT
   - Block malicious IPs/domains at firewall and proxy
   - Isolate affected endpoints from the network
   - Disable compromised user accounts

3. INVESTIGATION
   - Correlate the IOC with related indicators in SENTINEL
   - Review MITRE ATT&CK mappings to understand the attack stage
   - Check logs (SIEM, EDR, proxy) for additional activity
   - Use AI Analysis for automated threat assessment

4. ERADICATION
   - Remove malware and persistence mechanisms
   - Patch exploited vulnerabilities
   - Reset compromised credentials

5. RECOVERY
   - Restore systems from clean backups
   - Re-enable network access gradually
   - Monitor for re-infection

6. POST-INCIDENT
   - Document findings in a report (use SENTINEL's report generator)
   - Update detection rules and blocklists
   - Conduct lessons learned with the team`,

  'what is a c2 server': `A Command and Control (C2) server is infrastructure used by attackers to communicate with compromised systems (implants/agents). Key characteristics:

PURPOSE:
- Send commands to malware on victim machines
- Exfiltrate stolen data
- Deploy additional payloads
- Maintain persistent access

DETECTION IN SENTINEL:
- IP IOCs with high threat scores from multiple feeds
- Domains with short lifespans or DGA-like patterns
- URLs matching known C2 framework paths (Cobalt Strike, Metasploit, etc.)
- Beaconing patterns visible in network logs

COMMON C2 FRAMEWORKS:
- Cobalt Strike — Most widely used by APTs and red teams
- Metasploit — Open-source penetration testing framework
- Sliver — Modern open-source C2
- Brute Ratel — Newer, designed to evade EDR

RESPONSE:
- Block C2 IPs/domains immediately at network perimeter
- Search for beaconing activity in your environment
- Investigate all hosts that communicated with the C2
- Check for lateral movement from compromised hosts`,

  'default': `I'm SENTINEL AI, your threat intelligence assistant. Here are some topics I can help with:

- "What are IOCs?" — Learn about Indicators of Compromise
- "How does SENTINEL work?" — Platform overview and features
- "What is MITRE ATT&CK?" — Attack framework explained
- "How to investigate an IOC" — Step-by-step investigation workflow
- "What are threat feeds?" — Understanding threat intelligence feeds
- "Explain threat scoring" — How SENTINEL scores threats (0-100)
- "Incident response steps" — IR playbook for critical alerts
- "What is a C2 server?" — Command & Control infrastructure
- "What is threat intelligence?" — TI fundamentals

Type any question about cybersecurity, threat intelligence, or SENTINEL platform features!

Note: For AI-powered responses, ensure your GROQ_API_KEY is configured.`,
};

function matchFAQ(input: string): string {
  const normalized = input.toLowerCase().replace(/[?!.,]/g, '').trim();

  const keywordMap: [string[], string][] = [
    [['what are ioc', 'what is an ioc', 'ioc types', 'types of ioc', 'indicator of compromise', 'what is ioc'], 'what are iocs'],
    [['threat intelligence', 'what is ti', 'what is threat intel'], 'what is threat intelligence'],
    [['how does sentinel', 'how sentinel works', 'sentinel features', 'about sentinel', 'what is sentinel'], 'how does sentinel work'],
    [['mitre att', 'mitre attack', 'attack framework', 'what is att&ck', 'attack matrix'], 'what is mitre attack'],
    [['investigate', 'investigation', 'how to investigate', 'analyze ioc', 'triage'], 'how to investigate an ioc'],
    [['threat feed', 'what are feeds', 'feed sources', 'otx', 'abuseipdb'], 'what are threat feeds'],
    [['threat scor', 'scoring', 'score meaning', 'score range', 'what does the score'], 'explain threat scoring'],
    [['incident response', 'ir steps', 'respond to alert', 'critical alert', 'playbook'], 'incident response steps'],
    [['c2', 'c&c', 'command and control', 'command & control', 'cobalt strike', 'beacon'], 'what is a c2 server'],
  ];

  for (const [keywords, faqKey] of keywordMap) {
    if (keywords.some((kw) => normalized.includes(kw))) {
      return faqResponses[faqKey];
    }
  }

  return faqResponses['default'];
}

export default function AIAssistantPage() {
  const [messages, setMessages] = useState<AIChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function sendMessage(content: string) {
    if (!content.trim() || loading) return;

    const userMessage: AIChatMessage = { role: 'user', content: content.trim() };
    const updatedMessages = [...messages, userMessage];
    setMessages(updatedMessages);
    setInput('');
    setLoading(true);

    try {
      const response = await chatWithAI(updatedMessages);
      setMessages([...updatedMessages, { role: 'assistant', content: response.response }]);
    } catch {
      // Fallback to built-in FAQ responses when API is unavailable
      const faqAnswer = matchFAQ(content);
      setMessages([
        ...updatedMessages,
        { role: 'assistant', content: faqAnswer },
      ]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  }

  return (
    <div className="flex flex-col h-[calc(100vh-3rem)]">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-sentinel-border">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/20">
            <Sparkles className="w-5 h-5 text-sentinel-accent" />
          </div>
          <div>
            <h1 className="text-lg font-display font-bold text-sentinel-text-primary">AI Assistant</h1>
            <p className="text-xs font-mono text-sentinel-text-muted">
              Threat intelligence analysis powered by Groq / Llama 3.3
            </p>
          </div>
        </div>
        {messages.length > 0 && (
          <button
            onClick={() => setMessages([])}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono rounded border border-sentinel-border text-sentinel-text-muted hover:text-sentinel-danger hover:border-sentinel-danger/30 transition-colors"
          >
            <Trash2 className="w-3 h-3" />
            CLEAR
          </button>
        )}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto py-4 space-y-4">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <div className="p-4 rounded-full bg-sentinel-accent/5 border border-sentinel-accent/10 mb-4">
              <Bot className="w-10 h-10 text-sentinel-accent/50" />
            </div>
            <h2 className="text-sm font-display font-semibold text-sentinel-text-primary mb-1">
              SENTINEL AI Assistant
            </h2>
            <p className="text-xs font-mono text-sentinel-text-muted mb-6 max-w-md">
              Ask questions about threats, IOCs, attack patterns, incident response, or any cybersecurity topic.
            </p>
            <div className="grid grid-cols-2 gap-2 w-full max-w-lg">
              {quickPrompts.map((qp) => (
                <button
                  key={qp.label}
                  onClick={() => sendMessage(qp.prompt)}
                  className="p-3 rounded text-left border border-sentinel-border bg-sentinel-bg-secondary hover:border-sentinel-accent/30 hover:bg-sentinel-accent/5 transition-colors group"
                >
                  <p className="text-xs font-mono font-semibold text-sentinel-text-secondary group-hover:text-sentinel-accent transition-colors">
                    {qp.label}
                  </p>
                  <p className="text-[10px] font-mono text-sentinel-text-muted mt-1 line-clamp-2">
                    {qp.prompt}
                  </p>
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg, i) => (
            <div
              key={i}
              className={cn(
                'flex gap-3 animate-fade-in',
                msg.role === 'user' ? 'justify-end' : 'justify-start'
              )}
            >
              {msg.role === 'assistant' && (
                <div className="flex-shrink-0 w-7 h-7 rounded bg-sentinel-accent/10 border border-sentinel-accent/20 flex items-center justify-center">
                  <Bot className="w-4 h-4 text-sentinel-accent" />
                </div>
              )}
              <div
                className={cn(
                  'max-w-[75%] rounded-lg px-4 py-3 text-xs font-mono leading-relaxed',
                  msg.role === 'user'
                    ? 'bg-sentinel-accent/10 border border-sentinel-accent/20 text-sentinel-text-primary'
                    : 'bg-sentinel-bg-secondary border border-sentinel-border text-sentinel-text-secondary'
                )}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>
              </div>
              {msg.role === 'user' && (
                <div className="flex-shrink-0 w-7 h-7 rounded bg-sentinel-bg-tertiary border border-sentinel-border flex items-center justify-center">
                  <User className="w-4 h-4 text-sentinel-text-muted" />
                </div>
              )}
            </div>
          ))
        )}

        {loading && (
          <div className="flex gap-3 animate-fade-in">
            <div className="flex-shrink-0 w-7 h-7 rounded bg-sentinel-accent/10 border border-sentinel-accent/20 flex items-center justify-center">
              <Bot className="w-4 h-4 text-sentinel-accent" />
            </div>
            <div className="bg-sentinel-bg-secondary border border-sentinel-border rounded-lg px-4 py-3">
              <div className="flex items-center gap-2 text-xs font-mono text-sentinel-text-muted">
                <Loader2 className="w-3 h-3 animate-spin" />
                Analyzing...
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="border-t border-sentinel-border pt-4">
        <div className="flex gap-2">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about threats, IOCs, attack patterns..."
            rows={1}
            className="flex-1 px-4 py-3 rounded-lg bg-sentinel-bg-secondary border border-sentinel-border text-sm font-mono text-sentinel-text-primary placeholder:text-sentinel-text-muted outline-none focus:border-sentinel-accent/40 resize-none"
          />
          <button
            onClick={() => sendMessage(input)}
            disabled={!input.trim() || loading}
            className="px-4 py-3 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent hover:bg-sentinel-accent/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
        <p className="text-[10px] font-mono text-sentinel-text-muted mt-2 text-center">
          Powered by Groq / Llama 3.3 70B. Responses are AI-generated and should be verified.
        </p>
      </div>
    </div>
  );
}
