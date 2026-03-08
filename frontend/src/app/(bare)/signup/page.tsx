'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import { UserPlus, Mail, Lock, User } from 'lucide-react';
import { registerUser } from '@/lib/api';
import { useAuth } from '@/lib/auth';

export default function SignupPage() {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    fullName: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const { login } = useAuth();

  const validateForm = () => {
    if (!formData.username.trim()) {
      setError('Username is required');
      return false;
    }
    if (formData.username.length < 3) {
      setError('Username must be at least 3 characters');
      return false;
    }
    if (!formData.email.trim()) {
      setError('Email is required');
      return false;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      setError('Invalid email format');
      return false;
    }
    if (!formData.password) {
      setError('Password is required');
      return false;
    }
    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters');
      return false;
    }
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return false;
    }
    return true;
  };

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');

    if (!validateForm()) {
      return;
    }

    setLoading(true);
    try {
      const res = await registerUser({
        username: formData.username,
        email: formData.email,
        password: formData.password,
        full_name: formData.fullName || undefined,
      });
      login(res.access_token, res.user);
      // Redirect based on user role
      const redirectPath = res.user.role === 'admin' ? '/dashboard' : '/analytics';
      router.push(redirectPath);
    } catch (err: any) {
      setError(err.message || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  };

  return (
    <div className="flex items-center justify-center min-h-screen py-8">
      <div className="sentinel-card w-full max-w-md p-8 animate-fade-in">
        {/* Logo */}
        <div className="flex items-center justify-center mb-8">
          <Image
            src="/images/Wiestell-Logo.png"
            alt="Wiestell Logo"
            width={180}
            height={60}
            className="object-contain"
            priority
          />
        </div>

        <h2 className="text-sm font-display font-semibold text-sentinel-text-primary mb-5 text-center">
          Create Account
        </h2>

        {error && (
          <div className="mb-4 p-2.5 rounded bg-red-500/5 border border-red-500/20">
            <p className="text-xs font-mono text-red-400 text-center">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Username */}
          <div>
            <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
              Username *
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleChange}
                placeholder="Enter username"
                autoFocus
                className="w-full pl-10 pr-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
              />
            </div>
          </div>

          {/* Full Name */}
          <div>
            <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
              Full Name (Optional)
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type="text"
                name="fullName"
                value={formData.fullName}
                onChange={handleChange}
                placeholder="Enter full name"
                className="w-full pl-10 pr-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
              />
            </div>
          </div>

          {/* Email */}
          <div>
            <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
              Email *
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="your@email.com"
                className="w-full pl-10 pr-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
              Password *
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                placeholder="Minimum 6 characters"
                className="w-full pl-10 pr-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
              />
            </div>
          </div>

          {/* Confirm Password */}
          <div>
            <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
              Confirm Password *
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
              <input
                type="password"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                placeholder="Re-enter password"
                className="w-full pl-10 pr-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-xs font-mono font-semibold hover:bg-sentinel-accent/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            <UserPlus className="w-3.5 h-3.5" />
            {loading ? 'CREATING ACCOUNT...' : 'CREATE ACCOUNT'}
          </button>
        </form>

        <p className="text-center text-[10px] font-mono text-sentinel-text-muted mt-5">
          Already have an account?{' '}
          <button
            onClick={() => router.push('/login')}
            className="text-sentinel-accent hover:underline"
          >
            Sign in
          </button>
        </p>
      </div>
    </div>
  );
}
