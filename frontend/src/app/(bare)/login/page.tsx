'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, LogIn } from 'lucide-react';
import { loginUser } from '@/lib/api';
import { useAuth } from '@/lib/auth';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const { login } = useAuth();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!username.trim() || !password.trim()) {
      setError('Username and password are required.');
      return;
    }
    setLoading(true);
    try {
      const res = await loginUser({ username, password });
      login(res.access_token, res.user);
      router.push('/dashboard');
    } catch {
      setError('Invalid username or password.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex items-center justify-center min-h-[80vh]">
      <div className="sentinel-card w-full max-w-sm p-8 animate-fade-in">
        {/* Logo */}
        <div className="flex items-center gap-3 mb-8 justify-center">
          <Shield className="w-8 h-8 text-sentinel-accent" />
          <div>
            <h1 className="text-lg font-bold font-display text-sentinel-accent tracking-wider">SENTINEL</h1>
            <p className="text-[10px] font-mono text-sentinel-text-muted tracking-wide">Threat Intelligence Platform</p>
          </div>
        </div>

        <h2 className="text-sm font-display font-semibold text-sentinel-text-primary mb-5 text-center">Sign In</h2>

        {error && (
          <div className="mb-4 p-2.5 rounded bg-red-500/5 border border-red-500/20">
            <p className="text-xs font-mono text-red-400 text-center">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              autoFocus
              className="w-full px-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
            />
          </div>
          <div>
            <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              className="w-full px-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-xs font-mono font-semibold hover:bg-sentinel-accent/20 disabled:opacity-30 transition-colors"
          >
            <LogIn className="w-3.5 h-3.5" />
            {loading ? 'SIGNING IN...' : 'SIGN IN'}
          </button>
        </form>

        <p className="text-center text-[10px] font-mono text-sentinel-text-muted mt-5">
          No account?{' '}
          <button
            onClick={() => router.push('/profile')}
            className="text-sentinel-accent hover:underline"
          >
            Register here
          </button>
        </p>
      </div>
    </div>
  );
}
