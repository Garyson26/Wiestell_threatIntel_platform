export interface BlogPost {
  slug: string;
  title: string;
  description: string;
  content: string;
  author: string;
  publishedAt: string;
  readTime: string;
  category: 'Threat Intelligence' | 'IOC Analysis' | 'Security Research' | 'Tutorials';
  tags: string[];
  featured?: boolean;
}

export interface BlogPostMetadata {
  slug: string;
  title: string;
  description: string;
  author: string;
  publishedAt: string;
  readTime: string;
  category: string;
  tags: string[];
  featured?: boolean;
}
