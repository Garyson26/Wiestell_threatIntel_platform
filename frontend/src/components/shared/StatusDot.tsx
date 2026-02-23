import { cn } from '@/lib/utils';

interface StatusDotProps {
  status: 'healthy' | 'degraded' | 'offline' | 'disabled' | 'never_synced' | string;
  size?: 'sm' | 'md';
}

const statusColors: Record<string, string> = {
  healthy: 'bg-emerald-400',
  degraded: 'bg-amber-400',
  offline: 'bg-red-400',
  disabled: 'bg-slate-500',
  never_synced: 'bg-slate-500',
  success: 'bg-emerald-400',
  failed: 'bg-red-400',
};

export default function StatusDot({ status, size = 'sm' }: StatusDotProps) {
  const color = statusColors[status] || 'bg-slate-500';
  const sizeClass = size === 'md' ? 'w-2.5 h-2.5' : 'w-1.5 h-1.5';

  return (
    <span className={cn('rounded-full inline-block status-dot', color, sizeClass)} />
  );
}
