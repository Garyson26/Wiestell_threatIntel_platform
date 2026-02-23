'use client';

import { useState, useEffect } from 'react';
import { User, UserPlus, Shield, Mail, Clock } from 'lucide-react';
import { registerUser, getUsers } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { formatDate } from '@/lib/utils';
import type { UserProfile } from '@/lib/types';

export default function ProfilePage() {
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [showRegister, setShowRegister] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const { login } = useAuth();

  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    full_name: '',
    role: 'analyst',
  });

  useEffect(() => {
    loadUsers();
  }, []);

  async function loadUsers() {
    setLoading(true);
    try {
      const data = await getUsers();
      setUsers(data.items);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (!form.username.trim() || !form.email.trim() || !form.password.trim()) {
      setError('Username, email, and password are required.');
      return;
    }
    setRegistering(true);
    try {
      const res = await registerUser({
        username: form.username,
        email: form.email,
        password: form.password,
        full_name: form.full_name || undefined,
        role: form.role,
      });
      login(res.access_token, res.user);
      setSuccess(`User "${form.username}" registered and signed in.`);
      setForm({ username: '', email: '', password: '', full_name: '', role: 'analyst' });
      setShowRegister(false);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed.');
    } finally {
      setRegistering(false);
    }
  }

  const roleColor = (role: string) => {
    switch (role) {
      case 'admin': return 'text-red-400 bg-red-500/10';
      case 'analyst': return 'text-sentinel-accent bg-sentinel-accent/10';
      case 'viewer': return 'text-sentinel-text-muted bg-sentinel-bg-tertiary';
      default: return 'text-sentinel-text-muted bg-sentinel-bg-tertiary';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-display font-bold text-sentinel-text-primary">User Management</h1>
          <p className="text-xs font-mono text-sentinel-text-muted mt-0.5">
            Register new users and manage profiles
          </p>
        </div>
        <button
          onClick={() => { setShowRegister(!showRegister); setError(''); setSuccess(''); }}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent hover:bg-sentinel-accent/20 transition-colors"
        >
          <UserPlus className="w-3 h-3" />
          REGISTER USER
        </button>
      </div>

      {/* Status Messages */}
      {error && (
        <div className="sentinel-card p-3 border-red-500/30 bg-red-500/5">
          <p className="text-xs font-mono text-red-400">{error}</p>
        </div>
      )}
      {success && (
        <div className="sentinel-card p-3 border-green-500/30 bg-green-500/5">
          <p className="text-xs font-mono text-green-400">{success}</p>
        </div>
      )}

      {/* Registration Form */}
      {showRegister && (
        <div className="sentinel-card p-5 animate-fade-in">
          <h2 className="text-sm font-display font-semibold text-sentinel-text-primary mb-4">New User Registration</h2>
          <form onSubmit={handleRegister} className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Username *</label>
                <input
                  type="text"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  placeholder="e.g., jsmith"
                  className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Full Name</label>
                <input
                  type="text"
                  value={form.full_name}
                  onChange={(e) => setForm({ ...form, full_name: e.target.value })}
                  placeholder="e.g., John Smith"
                  className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Email *</label>
                <input
                  type="email"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder="user@example.com"
                  className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Password *</label>
                <input
                  type="password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder="Min 6 characters"
                  className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                />
              </div>
            </div>
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Role</label>
              <select
                value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value })}
                className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
              >
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
            <div className="flex gap-2 pt-2">
              <button
                type="submit"
                disabled={registering}
                className="px-4 py-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-xs font-mono font-semibold hover:bg-sentinel-accent/20 disabled:opacity-30 transition-colors"
              >
                {registering ? 'REGISTERING...' : 'REGISTER'}
              </button>
              <button
                type="button"
                onClick={() => setShowRegister(false)}
                className="px-4 py-2 rounded border border-sentinel-border text-xs font-mono text-sentinel-text-secondary hover:text-sentinel-text-primary transition-colors"
              >
                CANCEL
              </button>
            </div>
          </form>
        </div>
      )}

      {/* User List */}
      {loading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="sentinel-card p-5 animate-pulse">
              <div className="h-4 w-48 bg-sentinel-bg-tertiary rounded mb-2" />
              <div className="h-3 w-64 bg-sentinel-bg-tertiary rounded" />
            </div>
          ))}
        </div>
      ) : users.length === 0 ? (
        <div className="sentinel-card p-12 text-center">
          <User className="w-10 h-10 text-sentinel-text-muted mx-auto mb-3" />
          <p className="text-sentinel-text-muted text-sm font-mono">No users registered yet</p>
          <p className="text-sentinel-text-muted text-xs font-mono mt-1">Click &quot;Register User&quot; to create the first account</p>
        </div>
      ) : (
        <div className="space-y-3">
          {users.map((user, i) => (
            <div
              key={user.id}
              className="sentinel-card p-5 animate-fade-in"
              style={{ animationDelay: `${i * 40}ms` }}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/20 flex items-center justify-center">
                    <User className="w-4 h-4 text-sentinel-accent" />
                  </div>
                  <div>
                    <h3 className="text-sm font-mono font-semibold text-sentinel-text-primary">
                      {user.full_name || user.username}
                    </h3>
                    <p className="text-[10px] font-mono text-sentinel-text-muted">@{user.username}</p>
                  </div>
                </div>
                <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded ${roleColor(user.role)}`}>
                  {user.role}
                </span>
              </div>
              <div className="flex items-center gap-4 ml-11 text-[11px] font-mono text-sentinel-text-muted">
                <span className="flex items-center gap-1">
                  <Mail className="w-3 h-3" />
                  {user.email}
                </span>
                <span className="flex items-center gap-1">
                  <Shield className="w-3 h-3" />
                  {user.is_active ? 'Active' : 'Inactive'}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Joined {formatDate(user.created_at)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
