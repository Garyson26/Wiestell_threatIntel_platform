import { BlogPost } from '@/types/blog';

// This would typically fetch from a CMS, API, or MDX files
// For demonstration, using static data
export const blogPosts: BlogPost[] = [
  {
    slug: 'understanding-ioc-analysis',
    title: 'Understanding IOC Analysis: A Complete Guide for Security Analysts',
    description: 'Learn how to effectively analyze Indicators of Compromise (IOCs) and integrate threat intelligence into your security workflow.',
    author: 'Wiestell Team',
    publishedAt: '2026-03-10',
    readTime: '8 min read',
    category: 'IOC Analysis',
    tags: ['IOC', 'Threat Intelligence', 'Security Operations'],
    featured: true,
    content: `
      <h2>What are Indicators of Compromise?</h2>
      <p>Indicators of Compromise (IOCs) are forensic artifacts that suggest a system has been breached or compromised by malicious actors...</p>
      
      <h2>Types of IOCs</h2>
      <p>Common IOC types include IP addresses, domain names, file hashes, URLs, and email addresses. Each type requires different analysis approaches...</p>
      
      <h2>Best Practices for IOC Analysis</h2>
      <p>When analyzing IOCs, always validate against multiple threat intelligence sources, check for false positives, and correlate with your environment...</p>
    `,
  },
  {
    slug: 'threat-intelligence-feeds-comparison',
    title: 'Comparing Open-Source Threat Intelligence Feeds in 2026',
    description: 'A comprehensive comparison of popular open-source threat intelligence feeds including AlienVault OTX, AbuseIPDB, and URLhaus.',
    author: 'Wiestell Team',
    publishedAt: '2026-03-08',
    readTime: '12 min read',
    category: 'Threat Intelligence',
    tags: ['Threat Feeds', 'Open Source', 'Comparison'],
    featured: true,
    content: `
      <h2>Introduction to Threat Intelligence Feeds</h2>
      <p>Open-source threat intelligence feeds provide free access to curated lists of malicious indicators...</p>
      
      <h2>AlienVault OTX</h2>
      <p>AlienVault's Open Threat Exchange is one of the largest community-driven threat intelligence platforms...</p>
      
      <h2>AbuseIPDB</h2>
      <p>Specializing in IP reputation, AbuseIPDB tracks malicious IP addresses reported by users worldwide...</p>
    `,
  },
  {
    slug: 'automating-threat-hunting',
    title: 'Automating Threat Hunting with APIs and Scripts',
    description: 'Build automated threat hunting workflows using threat intelligence APIs, Python scripts, and continuous monitoring.',
    author: 'Wiestell Team',
    publishedAt: '2026-03-05',
    readTime: '10 min read',
    category: 'Tutorials',
    tags: ['Automation', 'API', 'Python', 'Threat Hunting'],
    content: `
      <h2>Why Automate Threat Hunting?</h2>
      <p>Manual threat hunting is time-consuming and doesn't scale. Automation helps SOC teams process more data efficiently...</p>
      
      <h2>Using Threat Intelligence APIs</h2>
      <p>Most threat intelligence platforms offer REST APIs for programmatic access. Here's how to integrate them...</p>
      
      <h2>Example Python Script</h2>
      <pre><code>import requests

def check_ioc(indicator):
    response = requests.get(f"https://api.wiestell.com/v1/ioc/{indicator}")
    return response.json()
</code></pre>
    `,
  },
  {
    slug: 'mitre-attack-framework-integration',
    title: 'Integrating MITRE ATT&CK Framework with Threat Intelligence',
    description: 'Map threat intelligence IOCs to MITRE ATT&CK tactics and techniques for better threat context and response prioritization.',
    author: 'Wiestell Team',
    publishedAt: '2026-03-01',
    readTime: '15 min read',
    category: 'Security Research',
    tags: ['MITRE ATT&CK', 'Framework', 'Threat Intelligence'],
    content: `
      <h2>Understanding MITRE ATT&CK</h2>
      <p>The MITRE ATT&CK framework is a knowledge base of adversary tactics and techniques based on real-world observations...</p>
      
      <h2>Mapping IOCs to ATT&CK</h2>
      <p>By mapping IOCs to specific tactics and techniques, security teams can better understand attack patterns...</p>
      
      <h2>Practical Implementation</h2>
      <p>Integrate ATT&CK mapping into your threat intelligence platform to automatically classify threats...</p>
    `,
  },
  {
    slug: 'building-custom-threat-feeds',
    title: 'Building Your Own Custom Threat Intelligence Feed',
    description: 'Step-by-step guide to creating, maintaining, and sharing custom threat intelligence feeds for your organization.',
    author: 'Wiestell Team',
    publishedAt: '2026-02-25',
    readTime: '11 min read',
    category: 'Tutorials',
    tags: ['Custom Feeds', 'Development', 'STIX/TAXII'],
    content: `
      <h2>Why Create Custom Feeds?</h2>
      <p>While public feeds are valuable, custom feeds tailored to your environment provide more relevant intelligence...</p>
      
      <h2>Data Collection Methods</h2>
      <p>Collect IOCs from your own honeypots, SIEM alerts, threat hunting activities, and partner sharing...</p>
      
      <h2>Feed Format Standards</h2>
      <p>Use STIX/TAXII standards for compatibility with existing threat intelligence platforms...</p>
    `,
  },
  {
    slug: 'false-positive-reduction-strategies',
    title: 'Reducing False Positives in Threat Intelligence Systems',
    description: 'Proven strategies and techniques to minimize false positives and improve the signal-to-noise ratio in your threat intelligence.',
    author: 'Wiestell Team',
    publishedAt: '2026-02-20',
    readTime: '9 min read',
    category: 'Security Research',
    tags: ['False Positives', 'Data Quality', 'Best Practices'],
    content: `
      <h2>The False Positive Problem</h2>
      <p>False positives waste analyst time and reduce trust in threat intelligence systems...</p>
      
      <h2>Multi-Source Validation</h2>
      <p>Never rely on a single threat intelligence source. Cross-reference IOCs across multiple feeds...</p>
      
      <h2>Contextual Analysis</h2>
      <p>Consider the context: age of the indicator, confidence scores, and historical activity patterns...</p>
    `,
  },
];

// Simulate API fetch - replace with actual API call or CMS integration
export async function getBlogPosts(): Promise<BlogPost[]> {
  // Simulate network delay
  await new Promise((resolve) => setTimeout(resolve, 100));
  return blogPosts;
}

export async function getBlogPost(slug: string): Promise<BlogPost | null> {
  // Simulate network delay
  await new Promise((resolve) => setTimeout(resolve, 100));
  return blogPosts.find((post) => post.slug === slug) || null;
}

export async function getFeaturedPosts(): Promise<BlogPost[]> {
  await new Promise((resolve) => setTimeout(resolve, 100));
  return blogPosts.filter((post) => post.featured);
}
