import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ArrowLeft, Clock, Calendar, Tag, User } from 'lucide-react';
import { getBlogPost, getBlogPosts } from '@/lib/blog';

interface BlogPostPageProps {
  params: Promise<{
    slug: string;
  }>;
}

// Generate static paths at build time
export async function generateStaticParams() {
  const posts = await getBlogPosts();
  
  return posts.map((post) => ({
    slug: post.slug,
  }));
}

// Generate metadata for each post
export async function generateMetadata({ params }: BlogPostPageProps): Promise<Metadata> {
  const { slug } = await params;
  const post = await getBlogPost(slug);
  
  if (!post) {
    return {
      title: 'Post Not Found',
    };
  }

  return {
    title: post.title,
    description: post.description,
    openGraph: {
      title: post.title,
      description: post.description,
      type: 'article',
      publishedTime: post.publishedAt,
      authors: [post.author],
      tags: post.tags,
    },
  };
}

export default async function BlogPostPage({ params }: BlogPostPageProps) {
  // Server Component - fetch post data
  const { slug } = await params;
  const post = await getBlogPost(slug);

  if (!post) {
    notFound();
  }

  return (
    <div className="min-h-screen bg-sentinel-bg-primary">
      {/* Header */}
      <header className="border-b border-sentinel-border bg-sentinel-bg-secondary/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <Link
            href="/blog"
            className="inline-flex items-center gap-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Blog
          </Link>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-12">
        <article className="max-w-4xl mx-auto">
          {/* Article Header */}
          <header className="mb-12">
            <div className="flex items-center gap-2 mb-4">
              <span className="text-xs font-mono font-semibold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30">
                {post.category}
              </span>
              <span className="text-xs font-mono text-sentinel-text-muted flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {post.readTime}
              </span>
            </div>

            <h1 className="text-4xl md:text-5xl font-bold font-display text-sentinel-text-primary mb-6 leading-tight">
              {post.title}
            </h1>

            <p className="text-lg text-sentinel-text-secondary font-mono mb-6">
              {post.description}
            </p>

            {/* Meta Information */}
            <div className="flex flex-wrap items-center gap-4 pb-6 border-b border-sentinel-border">
              <div className="flex items-center gap-2 text-sm font-mono text-sentinel-text-muted">
                <User className="w-4 h-4" />
                <span>{post.author}</span>
              </div>
              <div className="flex items-center gap-2 text-sm font-mono text-sentinel-text-muted">
                <Calendar className="w-4 h-4" />
                <span>
                  {new Date(post.publishedAt).toLocaleDateString('en-US', {
                    month: 'long',
                    day: 'numeric',
                    year: 'numeric',
                  })}
                </span>
              </div>
            </div>

            {/* Tags */}
            <div className="flex flex-wrap gap-2 mt-6">
              {post.tags.map((tag) => (
                <span
                  key={tag}
                  className="text-xs font-mono text-sentinel-text-secondary flex items-center gap-1 px-3 py-1 rounded-full bg-sentinel-bg-secondary border border-sentinel-border"
                >
                  <Tag className="w-3 h-3" />
                  {tag}
                </span>
              ))}
            </div>
          </header>

          {/* Article Content */}
          <div className="sentinel-card p-8 md:p-12">
            <div
              className="prose prose-invert max-w-none
                prose-headings:font-display prose-headings:text-sentinel-text-primary
                prose-h2:text-2xl prose-h2:font-semibold prose-h2:mb-4 prose-h2:mt-8
                prose-h3:text-xl prose-h3:font-semibold prose-h3:mb-3 prose-h3:mt-6
                prose-p:text-sentinel-text-secondary prose-p:font-mono prose-p:text-sm prose-p:leading-relaxed prose-p:mb-4
                prose-a:text-sentinel-accent prose-a:no-underline hover:prose-a:underline
                prose-strong:text-sentinel-text-primary prose-strong:font-semibold
                prose-code:text-sentinel-accent prose-code:font-mono prose-code:text-xs
                prose-pre:bg-sentinel-bg-primary prose-pre:border prose-pre:border-sentinel-border prose-pre:rounded prose-pre:p-4
                prose-ul:text-sentinel-text-secondary prose-ul:font-mono prose-ul:text-sm
                prose-ol:text-sentinel-text-secondary prose-ol:font-mono prose-ol:text-sm
                prose-li:mb-2"
              dangerouslySetInnerHTML={{ __html: post.content }}
            />
          </div>

          {/* Back to Blog CTA */}
          <div className="mt-12 text-center">
            <Link
              href="/blog"
              className="inline-flex items-center gap-2 px-6 py-3 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              View All Articles
            </Link>
          </div>
        </article>
      </main>
    </div>
  );
}
