import { cn } from '@/lib/utils';

interface LoadingSkeletonProps {
  className?: string;
  lines?: number;
}

export default function LoadingSkeleton({ className, lines = 3 }: LoadingSkeletonProps) {
  return (
    <div className={cn('space-y-3', className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className="h-4 bg-wiestell-bg-tertiary rounded animate-pulse"
          style={{ width: `${80 - i * 15}%` }}
        />
      ))}
    </div>
  );
}

export function CardSkeleton() {
  return (
    <div className="wiestell-card p-5 space-y-4 animate-pulse">
      <div className="h-3 w-24 bg-wiestell-bg-tertiary rounded" />
      <div className="h-8 w-32 bg-wiestell-bg-tertiary rounded" />
      <div className="h-2 w-full bg-wiestell-bg-tertiary rounded" />
    </div>
  );
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="wiestell-card overflow-hidden">
      <div className="p-4 border-b border-wiestell-border">
        <div className="h-4 w-48 bg-wiestell-bg-tertiary rounded animate-pulse" />
      </div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-4 py-3 border-b border-wiestell-border/50 animate-pulse">
          <div className="w-2 h-2 bg-wiestell-bg-tertiary rounded-full" />
          <div className="h-3 flex-1 bg-wiestell-bg-tertiary rounded" style={{ maxWidth: `${60 + Math.random() * 30}%` }} />
          <div className="h-3 w-12 bg-wiestell-bg-tertiary rounded" />
          <div className="h-3 w-20 bg-wiestell-bg-tertiary rounded" />
        </div>
      ))}
    </div>
  );
}
