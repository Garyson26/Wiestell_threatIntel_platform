import { cn } from '@/lib/utils';
import { getScoreBgClass } from '@/lib/utils';

interface ScoreBadgeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showBar?: boolean;
}

export default function ScoreBadge({ score, size = 'md', showBar = false }: ScoreBadgeProps) {
  const colorClass = getScoreBgClass(score);

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5',
    md: 'text-xs px-2 py-1',
    lg: 'text-sm px-3 py-1.5',
  };

  return (
    <div className="flex items-center gap-2">
      {showBar && (
        <div className="score-bar w-16">
          <div
            className="score-bar-fill"
            style={{
              width: `${score}%`,
              backgroundColor: score >= 76 ? '#ef4444' : score >= 51 ? '#f59e0b' : score >= 26 ? '#eab308' : '#10b981',
            }}
          />
        </div>
      )}
      <span
        className={cn(
          'font-mono font-semibold rounded border inline-block',
          sizeClasses[size],
          colorClass
        )}
      >
        {score}
      </span>
    </div>
  );
}
