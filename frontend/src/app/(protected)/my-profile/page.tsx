'use client';

import { useState, useEffect } from 'react';
import { User, Mail, Lock, Save, AlertCircle, CheckCircle2, Eye, EyeOff, Shield } from 'lucide-react';
import { getMe, updateMe, changePassword } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import type { UserProfile } from '@/lib/types';

export default function MyProfilePage() {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  
  const { user: authUser } = useAuth();

  const [form, setForm] = useState({
    full_name: '',
    email: '',
  });

  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });

  useEffect(() => {
    loadProfile();
  }, []);

  async function loadProfile() {
    setLoading(true);
    try {
      const data = await getMe();
      setUser(data);
      setForm({
        full_name: data.full_name || '',
        email: data.email || '',
      });
    } catch (err) {
      setError('Failed to load profile');
    } finally {
      setLoading(false);
    }
  }

  async function handleUpdate(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!form.full_name.trim()) {
      setError('Full name is required');
      return;
    }

    if (!form.email.trim()) {
      setError('Email is required');
      return;
    }

    setSaving(true);
    try {
      await updateMe({
        full_name: form.full_name,
        email: form.email,
      });
      setSuccess('Profile updated successfully');
      await loadProfile();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update profile');
    } finally {
      setSaving(false);
    }
  }

  async function handlePasswordChange(e: React.FormEvent) {
    e.preventDefault();
    setPasswordError('');
    setPasswordSuccess('');

    if (!passwordForm.current_password) {
      setPasswordError('Current password is required');
      return;
    }

    if (!passwordForm.new_password) {
      setPasswordError('New password is required');
      return;
    }

    if (passwordForm.new_password.length < 6) {
      setPasswordError('New password must be at least 6 characters');
      return;
    }

    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setPasswordError('New passwords do not match');
      return;
    }

    if (passwordForm.current_password === passwordForm.new_password) {
      setPasswordError('New password must be different from current password');
      return;
    }

    setSavingPassword(true);
    try {
      await changePassword({
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password,
      });
      setPasswordSuccess('Password changed successfully');
      setPasswordForm({
        current_password: '',
        new_password: '',
        confirm_password: '',
      });
    } catch (err) {
      setPasswordError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setSavingPassword(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="inline-block w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full animate-spin" />
          <p className="mt-2 text-xs font-mono text-sentinel-text-muted">Loading profile...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-xs font-mono text-sentinel-text-muted">Failed to load profile</p>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-display font-bold text-sentinel-text-primary">My Profile</h1>
        <p className="text-xs font-mono text-sentinel-text-muted mt-0.5">
          Manage your account information
        </p>
      </div>

      {/* Profile Card */}
      <div className="sentinel-card border border-sentinel-border p-6 space-y-6">
        {/* User Info Display */}
        <div className="flex items-center gap-4 pb-6 border-b border-sentinel-border/50">
          <div className="w-16 h-16 rounded-full bg-sentinel-accent/10 flex items-center justify-center">
            <User className="w-8 h-8 text-sentinel-accent" />
          </div>
          <div>
            <h2 className="text-sm font-mono font-semibold text-sentinel-text-primary">
              {user.full_name || user.username}
            </h2>
            <p className="text-xs font-mono text-sentinel-text-muted">{user.email}</p>
          </div>
        </div>

        {/* Edit Form */}
        <form onSubmit={handleUpdate} className="space-y-4">
          {/* Full Name */}
          <div>
            <label className="block text-xs font-mono font-medium text-sentinel-text-secondary mb-1.5">
              Full Name
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type="text"
                value={form.full_name}
                onChange={(e) => setForm({ ...form, full_name: e.target.value })}
                className="w-full pl-10 pr-3 py-2 text-sm font-mono bg-sentinel-bg-primary border border-sentinel-border rounded text-sentinel-text-primary placeholder:text-sentinel-text-muted focus:outline-none focus:border-sentinel-accent/40 transition-colors"
                placeholder="Enter your full name"
                required
              />
            </div>
          </div>

          {/* Email */}
          <div>
            <label className="block text-xs font-mono font-medium text-sentinel-text-secondary mb-1.5">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type="email"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                className="w-full pl-10 pr-3 py-2 text-sm font-mono bg-sentinel-bg-primary border border-sentinel-border rounded text-sentinel-text-primary placeholder:text-sentinel-text-muted focus:outline-none focus:border-sentinel-accent/40 transition-colors"
                placeholder="your.email@example.com"
                required
              />
            </div>
          </div>

          {/* Username (read-only) */}
          <div>
            <label className="block text-xs font-mono font-medium text-sentinel-text-secondary mb-1.5">
              Username
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type="text"
                value={user.username}
                disabled
                className="w-full pl-10 pr-3 py-2 text-sm font-mono bg-sentinel-bg-tertiary border border-sentinel-border rounded text-sentinel-text-muted cursor-not-allowed"
              />
            </div>
            <p className="mt-1 text-[10px] font-mono text-sentinel-text-muted">
              Username cannot be changed
            </p>
          </div>

          {/* Error/Success Messages */}
          {error && (
            <div className="flex items-start gap-2 p-3 rounded bg-sentinel-danger/10 border border-sentinel-danger/20">
              <AlertCircle className="w-4 h-4 text-sentinel-danger flex-shrink-0 mt-0.5" />
              <p className="text-xs font-mono text-sentinel-danger">{error}</p>
            </div>
          )}

          {success && (
            <div className="flex items-start gap-2 p-3 rounded bg-green-500/10 border border-green-500/20">
              <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
              <p className="text-xs font-mono text-green-500">{success}</p>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={saving}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-mono font-medium rounded bg-sentinel-accent text-white hover:bg-sentinel-accent/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </form>
      </div>

      {/* Additional Info */}
      <div className="sentinel-card border border-sentinel-border p-4">
        <h3 className="text-xs font-mono font-semibold text-sentinel-text-primary mb-2">
          Account Information
        </h3>
        <div className="space-y-2 text-[11px] font-mono">
          <div className="flex justify-between">
            <span className="text-sentinel-text-muted">Account ID:</span>
            <span className="text-sentinel-text-secondary font-mono">{user.id}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-sentinel-text-muted">Status:</span>
            <span className={`${user.is_active ? 'text-green-500' : 'text-sentinel-danger'}`}>
              {user.is_active ? 'Active' : 'Inactive'}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-sentinel-text-muted">Member Since:</span>
            <span className="text-sentinel-text-secondary">
              {new Date(user.created_at).toLocaleDateString()}
            </span>
          </div>
        </div>
      </div>

      {/* Password Change */}
      <div className="sentinel-card border border-sentinel-border p-6 space-y-4">
        <div className="flex items-center gap-2 pb-4 border-b border-sentinel-border/50">
          <Shield className="w-5 h-5 text-sentinel-accent" />
          <div>
            <h3 className="text-sm font-mono font-semibold text-sentinel-text-primary">
              Change Password
            </h3>
            <p className="text-[11px] font-mono text-sentinel-text-muted">
              Update your password to keep your account secure
            </p>
          </div>
        </div>

        <form onSubmit={handlePasswordChange} className="space-y-4">
          {/* Current Password */}
          <div>
            <label className="block text-xs font-mono font-medium text-sentinel-text-secondary mb-1.5">
              Current Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type={showCurrentPassword ? 'text' : 'password'}
                value={passwordForm.current_password}
                onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })}
                className="w-full pl-10 pr-10 py-2 text-sm font-mono bg-sentinel-bg-primary border border-sentinel-border rounded text-sentinel-text-primary placeholder:text-sentinel-text-muted focus:outline-none focus:border-sentinel-accent/40 transition-colors"
                placeholder="Enter current password"
                required
              />
              <button
                type="button"
                onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-sentinel-text-muted hover:text-sentinel-text-primary transition-colors"
              >
                {showCurrentPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* New Password */}
          <div>
            <label className="block text-xs font-mono font-medium text-sentinel-text-secondary mb-1.5">
              New Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type={showNewPassword ? 'text' : 'password'}
                value={passwordForm.new_password}
                onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                className="w-full pl-10 pr-10 py-2 text-sm font-mono bg-sentinel-bg-primary border border-sentinel-border rounded text-sentinel-text-primary placeholder:text-sentinel-text-muted focus:outline-none focus:border-sentinel-accent/40 transition-colors"
                placeholder="Enter new password (min 6 characters)"
                required
                minLength={6}
              />
              <button
                type="button"
                onClick={() => setShowNewPassword(!showNewPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-sentinel-text-muted hover:text-sentinel-text-primary transition-colors"
              >
                {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Confirm Password */}
          <div>
            <label className="block text-xs font-mono font-medium text-sentinel-text-secondary mb-1.5">
              Confirm New Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                value={passwordForm.confirm_password}
                onChange={(e) => setPasswordForm({ ...passwordForm, confirm_password: e.target.value })}
                className="w-full pl-10 pr-10 py-2 text-sm font-mono bg-sentinel-bg-primary border border-sentinel-border rounded text-sentinel-text-primary placeholder:text-sentinel-text-muted focus:outline-none focus:border-sentinel-accent/40 transition-colors"
                placeholder="Re-enter new password"
                required
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-sentinel-text-muted hover:text-sentinel-text-primary transition-colors"
              >
                {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Password Error/Success Messages */}
          {passwordError && (
            <div className="flex items-start gap-2 p-3 rounded bg-sentinel-danger/10 border border-sentinel-danger/20">
              <AlertCircle className="w-4 h-4 text-sentinel-danger flex-shrink-0 mt-0.5" />
              <p className="text-xs font-mono text-sentinel-danger">{passwordError}</p>
            </div>
          )}

          {passwordSuccess && (
            <div className="flex items-start gap-2 p-3 rounded bg-green-500/10 border border-green-500/20">
              <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
              <p className="text-xs font-mono text-green-500">{passwordSuccess}</p>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={savingPassword}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-mono font-medium rounded bg-sentinel-accent text-white hover:bg-sentinel-accent/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Lock className="w-4 h-4" />
            {savingPassword ? 'Changing Password...' : 'Change Password'}
          </button>
        </form>
      </div>
    </div>
  );
}
