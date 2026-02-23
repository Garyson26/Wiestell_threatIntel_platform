'use client';

import { cn } from '@/lib/utils';
import { getScoreCategory, getScoreColor } from '@/lib/utils';

interface ThreatGaugeProps {
  score: number;
  size?: number;
  loading?: boolean;
}

export default function ThreatGauge({ score, size = 180, loading = false }: ThreatGaugeProps) {
  const category = getScoreCategory(Math.round(score));
  const color = getScoreColor(Math.round(score));
  const radius = (size - 20) / 2;
  const circumference = Math.PI * radius;
  const progress = (Math.min(score, 100) / 100) * circumference;
  const center = size / 2;

  return (
    <div className="sentinel-card p-5 flex flex-col items-center">
      <p className="text-[10px] font-mono font-semibold uppercase tracking-widest text-sentinel-text-muted mb-3">
        THREAT LEVEL
      </p>
      {loading ? (
        <div className="flex flex-col items-center animate-pulse" style={{ width: size, height: size / 2 + 20 }}>
          <div className="w-full h-full flex flex-col items-center justify-end pb-2">
            <div className="h-8 w-16 bg-sentinel-bg-tertiary rounded mb-1" />
            <div className="h-3 w-12 bg-sentinel-bg-tertiary rounded" />
          </div>
        </div>
      ) : (
        <div className="relative" style={{ width: size, height: size / 2 + 20 }}>
          <svg
            width={size}
            height={size / 2 + 20}
            viewBox={`0 0 ${size} ${size / 2 + 20}`}
          >
            {/* Background arc */}
            <path
              d={`M 10 ${center} A ${radius} ${radius} 0 0 1 ${size - 10} ${center}`}
              fill="none"
              stroke="#1e293b"
              strokeWidth="8"
              strokeLinecap="round"
            />
            {/* Progress arc */}
            <path
              d={`M 10 ${center} A ${radius} ${radius} 0 0 1 ${size - 10} ${center}`}
              fill="none"
              stroke={color}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={`${progress} ${circumference}`}
              style={{
                filter: `drop-shadow(0 0 8px ${color}40)`,
                transition: 'stroke-dasharray 1s ease',
              }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-end pb-2">
            <span className="text-3xl font-mono font-bold" style={{ color }}>
              {Math.round(score)}
            </span>
            <span className="text-[10px] font-mono uppercase tracking-wider mt-1" style={{ color }}>
              {category}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
