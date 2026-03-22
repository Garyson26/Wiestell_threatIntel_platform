'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { LogIn, KeyRound, ArrowLeft, Shield, LogOut } from 'lucide-react';
import { loginUser, verifyOtp } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import OTPInput from '@/components/OTPInput';

export default function AdminLoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [otpStep, setOtpStep] = useState(false);
  const [otpMessage, setOtpMessage] = useState('');
  const router = useRouter();
  const { login, user, token, logout } = useAuth();

  // Redirect if user is already logged in
  useEffect(() => {
    if (user && token) {
      // Redirect based on user role
      const redirectPath = user.role === 'admin' ? '/dashboard' : '/analytics';
      router.push(redirectPath);
    }
  }, [user, token, router]);

  async function handleCredentialsSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!email.trim() || !password.trim()) {
      setError('Email and password are required.');
      return;
    }
    setLoading(true);
    try {
      const res = await loginUser({ email, password });
      setOtpMessage(res.message);
      setOtpStep(true);
    } catch (err: any) {
      setError(err.message || 'Invalid email or password.');
    } finally {
      setLoading(false);
    }
  }

  async function handleOtpSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!otp.trim()) {
      setError('OTP is required.');
      return;
    }
    setLoading(true);
    try {
      const res = await verifyOtp({ email, otp });
      
      // Verify that the user has admin role
      if (res.user.role !== 'admin') {
        setError('Access denied. Admin credentials required.');
        setLoading(false);
        return;
      }
      
      login(res.access_token, res.user);
      // Redirect to admin dashboard
      router.push('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Invalid OTP.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-sentinel-bg-primary">
      {/* Header */}
      <header className="border-b border-sentinel-border bg-sentinel-bg-secondary/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center">
            <Image
              src="/images/Wiestell-Logo.png"
              alt="Wiestell Logo"
              width={140}
              height={47}
              className="object-contain"
              priority
            />
          </Link>
          <div className="flex gap-3">
            <Link
              href="/about"
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              About
            </Link>
            <Link
              href="/contact"
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              Contact Us
            </Link>
            {user ? (
              <>
                <button
                  onClick={() => {
                    const dashboardPath = user.role === 'admin' ? '/dashboard' : '/analytics';
                    router.push(dashboardPath);
                  }}
                  className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
                >
                  Dashboard
                </button>
                <button
                  onClick={() => {
                    logout();
                    router.push('/');
                  }}
                  className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors flex items-center gap-1"
                >
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </>
            ) : (
              <>
                <Link
                  href="/login"
                  className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
                >
                  Login
                </Link>
                <Link
                  href="/admin"
                  className="px-4 py-2 text-sm font-mono text-sentinel-accent hover:text-sentinel-accent transition-colors font-semibold"
                >
                  Admin
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex items-center justify-center min-h-[calc(100vh-73px)] py-12">
        <div className="sentinel-card w-full max-w-sm p-8 animate-fade-in">
          {/* Admin Badge */}
          <div className="flex items-center justify-center gap-2 mb-6">
            <Shield className="w-4 h-4 text-sentinel-accent" />
            <h2 className="text-sm font-display font-semibold text-sentinel-text-primary">
              {otpStep ? 'Enter OTP' : 'Admin Sign In'}
            </h2>
          </div>

        {error && (
          <div className="mb-4 p-2.5 rounded bg-red-50 border border-red-200">
            <p className="text-xs font-mono text-red-700 text-center">{error}</p>
          </div>
        )}

        {otpMessage && otpStep && (
          <div className="mb-4 p-2.5 rounded bg-sentinel-accent/5 border border-sentinel-accent/20">
            <p className="text-xs font-mono text-sentinel-accent text-center">{otpMessage}</p>
          </div>
        )}

        {!otpStep ? (
          <form onSubmit={handleCredentialsSubmit} className="space-y-4">
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Admin Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter admin email"
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
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded bg-black text-white text-xs font-mono font-semibold hover:bg-gray-800 disabled:opacity-30 transition-colors"
            >
              <LogIn className="w-3.5 h-3.5" />
              {loading ? 'PROCESSING...' : 'CONTINUE'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleOtpSubmit} className="space-y-4">
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Enter OTP</label>
              <input
                type="text"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                placeholder="Enter 6-digit OTP"
                maxLength={6}
                autoFocus
                className="w-full px-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors text-center text-xl tracking-widest"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded bg-black text-white text-xs font-mono font-semibold hover:bg-gray-800 disabled:opacity-30 transition-colors"
            >
              <KeyRound className="w-3.5 h-3.5" />
              {loading ? 'VERIFYING...' : 'VERIFY OTP'}
            </button>
            <button
              type="button"
              onClick={() => {
                setOtpStep(false);
                setOtp('');
                setError('');
                setOtpMessage('');
              }}
              className="w-full text-xs font-mono text-sentinel-text-muted hover:text-sentinel-accent transition-colors"
            >
              ← Back to login
            </button>
          </form>
        )}

        <p className="text-center text-[10px] font-mono text-sentinel-text-muted mt-5">
          Not an admin?{' '}
          <button
            onClick={() => router.push('/login')}
            className="text-sentinel-accent hover:underline"
          >
            Login
          </button>
        </p>
      </div>
    </div>
    </div>
  );
}
