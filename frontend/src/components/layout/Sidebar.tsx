'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  Search,
  Rss,
  Grid3X3,
  Crosshair,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
  Activity,
  Database,
  Clock,
  Sparkles,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/ioc', label: 'IOC Search', icon: Search },
  { href: '/feeds', label: 'Threat Feeds', icon: Rss },
  { href: '/attack-map', label: 'ATT&CK Map', icon: Grid3X3 },
  { href: '/hunting', label: 'Threat Hunting', icon: Crosshair },
  { href: '/ai-assistant', label: 'AI Assistant', icon: Sparkles },
  { href: '/reports', label: 'Reports', icon: FileText },
  { href: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const pathname = usePathname();

  return (
    <aside
      className={cn(
        'flex flex-col h-screen border-r border-sentinel-border transition-all duration-300',
        'bg-sentinel-bg-secondary',
        collapsed ? 'w-16' : 'w-60'
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-sentinel-border">
        <Shield className="w-7 h-7 text-sentinel-accent flex-shrink-0" />
        {!collapsed && (
          <div>
            <h1 className="text-sm font-bold font-display text-sentinel-accent tracking-wider">
              SENTINEL
            </h1>
            <p className="text-[10px] font-mono text-sentinel-text-muted tracking-wide">
              TIP v1.0
            </p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 space-y-1 px-2 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-3 px-3 py-2.5 rounded text-sm font-mono transition-all duration-150',
                isActive
                  ? 'bg-sentinel-accent/10 text-sentinel-accent border border-sentinel-accent/20'
                  : 'text-sentinel-text-secondary hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover border border-transparent'
              )}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* System Status */}
      {!collapsed && (
        <div className="px-4 py-4 border-t border-sentinel-border space-y-2">
          <p className="text-[10px] font-mono text-sentinel-text-muted uppercase tracking-widest">
            System Status
          </p>
          <div className="space-y-1.5">
            <StatusLine icon={Activity} label="Feeds" value="Active" color="#10b981" />
            <StatusLine icon={Database} label="Database" value="Connected" color="#10b981" />
            <StatusLine icon={Clock} label="Last Sync" value="--" color="#64748b" />
          </div>
        </div>
      )}

      {/* Collapse Toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-center py-3 border-t border-sentinel-border text-sentinel-text-muted hover:text-sentinel-text-primary transition-colors"
      >
        {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
      </button>
    </aside>
  );
}

function StatusLine({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="flex items-center gap-2 text-xs font-mono">
      <span className="status-dot w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
      <Icon className="w-3 h-3 text-sentinel-text-muted" />
      <span className="text-sentinel-text-muted">{label}:</span>
      <span className="text-sentinel-text-secondary ml-auto">{value}</span>
    </div>
  );
}
