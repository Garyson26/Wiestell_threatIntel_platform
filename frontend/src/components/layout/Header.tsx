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
      const searchPath = user?.role === 'admin' ? '/ioc' : '/ioc-search';
      router.push(`${searchPath}?q=${encodeURIComponent(searchValue.trim())}`);
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
      case 'critical': return <AlertTriangle className="w-3 h-3 text-gray-600 flex-shrink-0" />;
      case 'warning': return <AlertCircle className="w-3 h-3 text-gray-700 flex-shrink-0" />;
      default: return <Info className="w-3 h-3 text-gray-700 flex-shrink-0" />;
    }
  };

  return (
    <header className="relative z-50 flex items-center justify-between h-14 px-6 border-b border-wiestell-border bg-wiestell-bg-secondary/80 backdrop-blur-sm">
      {/* Global Search */}
      <form onSubmit={handleSearch} className="flex items-center gap-2 flex-1 max-w-xl">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-wiestell-bg-primary border border-wiestell-border w-full focus-within:border-wiestell-accent/40 transition-colors">
          <Search className="w-4 h-4 text-wiestell-text-muted flex-shrink-0" />
          <input
            type="text"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            placeholder="Search IOCs (IP, domain, hash, URL)..."
            className="bg-transparent text-sm font-mono text-wiestell-text-primary placeholder:text-wiestell-text-muted w-full outline-none"
          />
        </div>
      </form>

      {/* Navigation Links - Only show on public pages */}
      {!pathname.startsWith('/dashboard') && 
       !pathname.startsWith('/analytics') && 
       !pathname.startsWith('/ioc') && 
       !pathname.startsWith('/feeds') && 
       !pathname.startsWith('/attack-map') && 
       !pathname.startsWith('/hunting') && 
       !pathname.startsWith('/ai-assistant') && 
       !pathname.startsWith('/reports') && 
       !pathname.startsWith('/settings') && 
       !pathname.startsWith('/profile') && 
       !pathname.startsWith('/my-profile') && 
       !pathname.startsWith('/submit') && 
       !pathname.startsWith('/history') && 
       !pathname.startsWith('/ioc-search') && (
        <nav className="flex items-center gap-1 mx-4">
          <button
            onClick={() => router.push('/about')}
            className={cn(
              'text-xs font-mono font-medium transition-colors px-3 py-1.5 rounded',
              pathname === '/about'
                ? 'text-wiestell-accent bg-wiestell-accent/10'
                : 'text-wiestell-text-secondary hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover'
            )}
          >
            About
          </button>
        </nav>
      )}

      {/* Right Side Actions */}
      <div className="flex items-center gap-3 ml-4">
        {/* Refresh Button */}
        <button
          onClick={handleRefresh}
          className="p-2 rounded text-wiestell-text-muted hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover transition-colors"
          title="Refresh page data"
        >
          <RefreshCw className={cn('w-4 h-4', refreshing && 'animate-spin')} />
        </button>

        {/* Notifications */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => { setShowNotifications(!showNotifications); setShowUserMenu(false); }}
            className="p-2 rounded text-wiestell-text-muted hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover transition-colors relative"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-wiestell-danger rounded-full" />
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 top-full mt-2 w-80 wiestell-card border border-wiestell-border shadow-xl z-50 max-h-96 flex flex-col animate-fade-in">
              <div className="px-4 py-3 border-b border-wiestell-border">
                <h3 className="text-xs font-mono font-semibold text-wiestell-text-primary uppercase tracking-wider">
                  Threat Alerts
                </h3>
              </div>
              <div className="overflow-y-auto flex-1">
                {notifications.length === 0 ? (
                  <div className="px-4 py-6 text-center">
                    <p className="text-xs font-mono text-wiestell-text-muted">No recent alerts</p>
                  </div>
                ) : (
                  notifications.map((n) => (
                    <button
                      key={n.id + n.timestamp}
                      onClick={() => { router.push(`/ioc/${n.id}`); setShowNotifications(false); }}
                      className="w-full px-4 py-3 border-b border-wiestell-border/50 hover:bg-wiestell-bg-hover transition-colors text-left"
                    >
                      <div className="flex items-start gap-2">
                        {levelIcon(n.level)}
                        <div className="min-w-0 flex-1">
                          <p className="text-xs font-mono text-wiestell-text-primary truncate">{n.message}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={cn(
                              'text-[10px] font-mono px-1.5 py-0.5 rounded',
                              n.level === 'critical' ? 'bg-gray-200 text-gray-600' :
                              n.level === 'warning' ? 'bg-gray-300 text-gray-700' :
                              'bg-gray-500/10 text-gray-300'
                            )}>
                              SCORE {n.threat_score}
                            </span>
                            <span className="text-[10px] font-mono text-wiestell-text-muted">
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
                ? 'text-wiestell-accent hover:bg-wiestell-accent/10'
                : 'text-wiestell-text-muted hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover'
            )}
          >
            <User className="w-4 h-4" />
            {user && (
              <span className="text-[11px] font-mono hidden sm:inline">{user.username}</span>
            )}
          </button>

          {showUserMenu && (
            <div className="absolute right-0 top-full mt-2 w-52 wiestell-card border border-wiestell-border shadow-xl z-50 animate-fade-in">
              {user ? (
                <>
                  <div className="px-4 py-3 border-b border-wiestell-border/50">
                    <p className="text-xs font-mono font-semibold text-wiestell-text-primary">{user.full_name || user.username}</p>
                    <p className="text-[10px] font-mono text-wiestell-text-muted">{user.email}</p>
                    {/* <span className="text-[10px] font-mono text-wiestell-accent uppercase">{user.role}</span> */}
                  </div>
                  {user.role === 'admin' && (
                    <>
                    <button
                      onClick={() => { router.push('/profile'); setShowUserMenu(false); }}
                      className="w-full px-4 py-2.5 text-left text-xs font-mono text-wiestell-text-secondary hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover transition-colors"
                    >
                      User Management
                    </button>
                
                  <button
                    onClick={() => { router.push('/settings'); setShowUserMenu(false); }}
                    className={cn(
                      'w-full px-4 py-2.5 text-left text-xs font-mono text-wiestell-text-secondary hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover transition-colors',
                      'border-t border-wiestell-border/50'
                    )}
                  >
                    Settings
                  </button>
                  </>
                    )}
                  <button
                    onClick={() => { router.push('/my-profile'); setShowUserMenu(false); }}
                    className={cn(
                      'w-full px-4 py-2.5 text-left text-xs font-mono text-wiestell-text-secondary hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover transition-colors',
                      user.role === 'admin' ? '' : 'border-t border-wiestell-border/50'
                    )}
                  >
                    My Profile
                  </button>
                  <button
                    onClick={handleLogout}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-gray-700 hover:bg-gray-200 transition-colors border-t border-wiestell-border/50 flex items-center gap-2"
                  >
                    <LogOut className="w-3 h-3" />
                    Sign Out
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => { router.push('/about'); setShowUserMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-wiestell-text-secondary hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover transition-colors flex items-center gap-2"
                  >
                    <Info className="w-3 h-3" />
                    About
                  </button>
                  <button
                    onClick={() => { router.push('/login'); setShowUserMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-wiestell-accent hover:bg-wiestell-accent/10 transition-colors flex items-center gap-2 border-t border-wiestell-border/50"
                  >
                    <LogIn className="w-3 h-3" />
                    Sign In
                  </button>
                  <button
                    onClick={() => { router.push('/signup'); setShowUserMenu(false); }}
                    className="w-full px-4 py-2.5 text-left text-xs font-mono text-wiestell-text-secondary hover:text-wiestell-text-primary hover:bg-wiestell-bg-hover transition-colors border-t border-wiestell-border/50"
                  >
                    Sign Up
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
