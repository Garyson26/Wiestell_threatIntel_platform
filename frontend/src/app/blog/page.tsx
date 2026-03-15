import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Clock, Tag, Calendar } from 'lucide-react';
import { getBlogPosts } from '@/lib/blog';

export const metadata: Metadata = {
  title: 'Blog',
  description: 'Technical articles, tutorials, and insights about threat intelligence, IOC analysis, and security research from the Wiestell team.',
};

export default async function BlogPage() {
  // Server Component - fetch data at build time
  const posts = await getBlogPosts();
  const featuredPosts = posts.filter((post) => post.featured);
  const regularPosts = posts.filter((post) => !post.featured);

  return (
    <div className="min-h-screen bg-sentinel-bg-primary">
      {/* Header */}
      <header className="border-b border-sentinel-border bg-sentinel-bg-secondary/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </Link>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-12">
        <div className="max-w-6xl mx-auto">
          {/* Page Title */}
          <div className="mb-12">
            <h1 className="text-4xl md:text-5xl font-bold font-display text-sentinel-text-primary mb-4">
              Threat Intelligence Blog
            </h1>
            <p className="text-lg text-sentinel-text-secondary font-mono">
              Technical articles, tutorials, and security research insights
            </p>
          </div>

          {/* Featured Posts */}
          {featuredPosts.length > 0 && (
            <section className="mb-16">
              <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-6 flex items-center gap-2">
                <span className="text-sentinel-accent">→</span> Featured Articles
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {featuredPosts.map((post) => (
                  <Link
                    key={post.slug}
                    href={`/blog/${post.slug}`}
                    className="sentinel-card p-6 hover:border-sentinel-accent/40 transition-all duration-200 group"
                  >
                    <div className="flex items-center gap-2 mb-3">
                      <span className="text-xs font-mono font-semibold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30">
                        {post.category}
                      </span>
                      <span className="text-xs font-mono text-sentinel-text-muted flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {post.readTime}
                      </span>
                    </div>
                    <h3 className="text-xl font-display font-semibold text-sentinel-text-primary mb-3 group-hover:text-sentinel-accent transition-colors">
                      {post.title}
                    </h3>
                    <p className="text-sm font-mono text-sentinel-text-secondary mb-4 line-clamp-2">
                      {post.description}
                    </p>
                    <div className="flex items-center justify-between text-xs font-mono text-sentinel-text-muted">
                      <span>{post.author}</span>
                      <span className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {new Date(post.publishedAt).toLocaleDateString('en-US', {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric',
                        })}
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            </section>
          )}

          {/* All Posts */}
          <section>
            <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-6 flex items-center gap-2">
              <span className="text-sentinel-accent">→</span> All Articles
            </h2>
            <div className="space-y-4">
              {regularPosts.map((post) => (
                <Link
                  key={post.slug}
                  href={`/blog/${post.slug}`}
                  className="sentinel-card p-6 hover:border-sentinel-accent/40 transition-all duration-200 group block"
                >
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-xs font-mono font-semibold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30">
                          {post.category}
                        </span>
                        <span className="text-xs font-mono text-sentinel-text-muted flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {post.readTime}
                        </span>
                      </div>
                      <h3 className="text-lg font-display font-semibold text-sentinel-text-primary mb-2 group-hover:text-sentinel-accent transition-colors">
                        {post.title}
                      </h3>
                      <p className="text-sm font-mono text-sentinel-text-secondary mb-3">
                        {post.description}
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {post.tags.map((tag) => (
                          <span
                            key={tag}
                            className="text-xs font-mono text-sentinel-text-muted flex items-center gap-1"
                          >
                            <Tag className="w-3 h-3" />
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="flex flex-col items-start md:items-end gap-1 text-xs font-mono text-sentinel-text-muted">
                      <span>{post.author}</span>
                      <span className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {new Date(post.publishedAt).toLocaleDateString('en-US', {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric',
                        })}
                      </span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
