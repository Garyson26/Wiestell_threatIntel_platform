'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { Search, Bell, User, RefreshCw, AlertTriangle, AlertCircle, Info, LogIn, LogOut } from 'lucide-react';
import { getNotifications } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { cn, formatDate } from '@/lib/utils';
import type { Notification } from '@/lib/types';

export default function Header() {
  const [searchValue, setSearchValue] = useState('');
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const router = useRouter();
  const pathname = usePathname();
  const notifRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);
  const { user, logout } = useAuth();

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchValue.trim()) {
      router.push(`/ioc?q=${encodeURIComponent(searchValue.trim())}`);
    }
  };

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
      if (userRef.current && !userRef.current.contains(e.target as Node)) {
        setShowUserMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  useEffect(() => {
    if (showNotifications) {
      getNotifications(15).then(setNotifications).catch(() => {});
    }
  }, [showNotifications]);

  const handleRefresh = () => {
    setRefreshing(true);
    router.refresh();
    setTimeout(() => setRefreshing(false), 1000);
  };

  const handleLogout = () => {
    logout();
    setShowUserMenu(false);
    router.push('/login');
  };

  const unreadCount = notifications.filter(n => n.level === 'critical').length;

  const levelIcon = (level: string) => {
    switch (level) {
      case 'critical': return <AlertTriangle className="w-3 h-3 text-red-400 flex-shrink-0" />;
      case 'warning': return <AlertCircle className="w-3 h-3 text-yellow-400 flex-shrink-0" />;
      default: return <Info className="w-3 h-3 text-blue-400 flex-shrink-0" />;
    }
  };

  return (
    <header className="flex items-center justify-between h-14 px-6 border-b border-sentinel-border bg-sentinel-bg-secondary/80 backdrop-blur-sm">
      {/* Global Search */}
      <form onSubmit={handleSearch} className="flex items-center gap-2 flex-1 max-w-xl">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-sentinel-bg-primary border border-sentinel-border w-full focus-within:border-sentinel-accent/40 transition-colors">
          <Search className="w-4 h-4 text-sentinel-text-muted flex-shrink-0" />
          <input
            type="text"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            placeholder="Search IOCs (IP, domain, hash, URL)..."
            className="bg-transparent text-sm font-mono text-sentinel-text-primary placeholder:text-sentinel-text-muted w-full outline-none"
          />
        </div>
      </form>

      {/* Right Side Actions */}
      <div className="flex items-center gap-3 ml-4">
        {/* Refresh Button */}
        <button
          onClick={handleRefresh}
          className="p-2 rounded text-sentinel-text-muted hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover transition-colors"
          title="Refresh page data"
        >
          <RefreshCw className={cn('w-4 h-4', refreshing && 'animate-spin')} />
        </button>

        {/* Notifications */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => { setShowNotifications(!showNotifications); setShowUserMenu(false); }}
            className="p-2 rounded text-sentinel-text-muted hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover transition-colors relative"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-sentinel-danger rounded-full" />
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 top-full mt-2 w-80 sentinel-card border border-sentinel-border shadow-xl z-50 max-h-96 flex flex-col animate-fade-in">
              <div className="px-4 py-3 border-b border-sentinel-border">
                <h3 className="text-xs font-mono font-semibold text-sentinel-text-primary uppercase tracking-wider">
                  Threat Alerts
                </h3>
              </div>
              <div className="overflow-y-auto flex-1">
                {notifications.length === 0 ? (
                  <div className="px-4 py-6 text-center">
                    <p className="text-xs font-mono text-sentinel-text-muted">No recent alerts</p>
                  </div>
                ) : (
                  notifications.map((n) => (
                    <button
                      key={n.id + n.timestamp}
                      onClick={() => { router.push(`/ioc/${n.id}`); setShowNotifications(false); }}
                      className="w-full px-4 py-3 border-b border-sentinel-border/50 hover:bg-sentinel-bg-hover transition-colors text-left"
                    >
                      <div className="flex items-start gap-2">
                        {levelIcon(n.level)}
                        <div className="min-w-0 flex-1">
                          <p className="text-xs font-mono text-sentinel-text-primary truncate">{n.message}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={cn(
                              'text-[10px] font-mono px-1.5 py-0.5 rounded',
                              n.level === 'critical' ? 'bg-red-500/10 text-red-400' :
                              n.level === 'warning' ? 'bg-yellow-500/10 text-yellow-400' :
                              'bg-blue-500/10 text-blue-400'
                            )}>
                              SCORE {n.threat_score}
                            </span>
                            <span className="text-[10px] font-mono text-sentinel-text-muted">
                              {formatDate(n.timestamp)}
                            </span>
                          </div>
                        </div>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Menu */}
        <div className="relative" ref={userRef}>
          <button
            onClick={() => { setShowUserMenu(!showUserMenu); setShowNotifications(false); }}
            className={cn(
              'flex items-center gap-2 p-2 rounded transition-colors',
              user
                ? 'text-sentinel-accent hover:bg-sentinel-accent/10'
                : 'text-sentinel-text-muted hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover'
            )}
          >
            <User className="w-4 h-4" />
            {user && (
              <span className="text-[11px] font-mono hidden sm:inline">{user.username}</span>
            )}
          </button>

          {showUserMenu && (
            <div className="absolute right-0 top-full mt-2 w-52 sentinel-card border border-sentinel-border shadow-xl z-50 animate-fade-in">
              {user ? (
                <>
                  <div className="px-4 py-3 border-b border-sentinel-border/50">
                    <p className="text-xs font-mono font-semibold text-sentinel-text-primary">{user.full_name || user.username}</p>
                    <p className="text-[10px] font-mono text-sentinel-text-muted">{user.email}</p>
                    <span className="text-[10px] font-mono text-sentinel-accent uppercase">{user.role}</span>
                  </div>
                  <button
                    onClick={() => { router.push('/profile'); setShowUserMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-sentinel-text-secondary hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover transition-colors"
                  >
                    User Management
                  </button>
                  <button
                    onClick={() => { router.push('/settings'); setShowUserMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-sentinel-text-secondary hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover transition-colors border-t border-sentinel-border/50"
                  >
                    Settings
                  </button>
                  <button
                    onClick={handleLogout}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-red-400 hover:bg-red-500/10 transition-colors border-t border-sentinel-border/50 flex items-center gap-2"
                  >
                    <LogOut className="w-3 h-3" />
                    Sign Out
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => { router.push('/login'); setShowUserMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-sentinel-accent hover:bg-sentinel-accent/10 transition-colors flex items-center gap-2"
                  >
                    <LogIn className="w-3 h-3" />
                    Sign In
                  </button>
                  <button
                    onClick={() => { router.push('/profile'); setShowUserMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-sentinel-text-secondary hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover transition-colors border-t border-sentinel-border/50"
                  >
                    Register
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
