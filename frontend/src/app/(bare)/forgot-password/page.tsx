'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { Mail, ArrowLeft, Send, CheckCircle2, LogOut } from 'lucide-react';
import { forgotPassword } from '@/lib/api';
import { useAuth } from '@/lib/auth';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [message, setMessage] = useState('');
  const router = useRouter();
  const { user, logout } = useAuth();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!email.trim()) {
      setError('Email is required.');
      return;
    }
    setLoading(true);
    try {
      const res = await forgotPassword({ email });
      setMessage(res.message);
      setSuccess(true);
      // Redirect to reset password page after 2 seconds
      setTimeout(() => {
        router.push(`/reset-password?email=${encodeURIComponent(email)}`);
      }, 2000);
    } catch (err: any) {
      setError(err.message || 'Failed to send password reset email.');
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
              </>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex items-center justify-center min-h-[calc(100vh-73px)] py-12">
        <div className="sentinel-card w-full max-w-sm p-8 animate-fade-in">
          {/* Header */}
          <div className="text-center mb-6">
            <h2 className="text-sm font-display font-semibold text-sentinel-text-primary mb-2">
              Forgot Password?
            </h2>
            <p className="text-xs font-mono text-sentinel-text-muted">
              Enter your email to receive a password reset OTP
            </p>
          </div>

        {error && (
          <div className="mb-4 p-2.5 rounded bg-red-50 border border-red-200">
            <p className="text-xs font-mono text-red-700 text-center">{error}</p>
          </div>
        )}

        {success ? (
          <div className="space-y-4">
            <div className="flex flex-col items-center justify-center py-6">
              <CheckCircle2 className="w-12 h-12 text-green-500 mb-3" />
              <p className="text-xs font-mono text-sentinel-text-primary text-center mb-2">
                {message}
              </p>
              <p className="text-xs font-mono text-sentinel-text-muted text-center">
                Redirecting to reset password page...
              </p>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
                Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="your.email@example.com"
                  autoFocus
                  className="w-full pl-10 pr-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded bg-black text-white text-xs font-mono font-semibold hover:bg-gray-800 disabled:opacity-30 transition-colors"
            >
              <Send className="w-3.5 h-3.5" />
              {loading ? 'SENDING...' : 'SEND RESET OTP'}
            </button>
          </form>
        )}

        {/* Back to Login */}
        <div className="mt-6 pt-4 border-t border-sentinel-border">
          <button
            onClick={() => router.push('/login')}
            className="w-full flex items-center justify-center gap-2 text-xs font-mono text-sentinel-text-muted hover:text-sentinel-accent transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Login
          </button>
        </div>
      </div>
    </div>
    </div>
  );
}
