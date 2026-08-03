'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { Lock, KeyRound, ArrowLeft, CheckCircle2, Eye, EyeOff, LogOut } from 'lucide-react';
import { resetPassword } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { consumeResetEmail } from '@/lib/passwordResetHandoff';
import OTPInput from '@/components/OTPInput';

function ResetPasswordForm() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const router = useRouter();
  const { user, logout } = useAuth();

  useEffect(() => {
    // Handed over in sessionStorage by /forgot-password, not in the URL — see
    // lib/passwordResetHandoff for why. Absent on a direct link or a new tab, in
    // which case the email field below is simply filled in by the user.
    const stored = consumeResetEmail();
    if (stored) {
      setEmail(stored);
    }
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');

    if (!email.trim()) {
      setError('Email is required.');
      return;
    }

    if (!otp.trim()) {
      setError('OTP is required.');
      return;
    }

    if (otp.length !== 6) {
      setError('OTP must be 6 digits.');
      return;
    }

    if (!newPassword.trim()) {
      setError('New password is required.');
      return;
    }

    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await resetPassword({ email, otp, new_password: newPassword });
      setSuccess(true);
      // Redirect to login after 3 seconds
      setTimeout(() => {
        router.push('/login');
      }, 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to reset password.');
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
            <Link
              href="/login"
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              Login
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex items-center justify-center min-h-[calc(100vh-73px)] py-12">
        <div className="sentinel-card w-full max-w-sm p-8 animate-fade-in">
          {/* Header */}
          <div className="text-center mb-6">
            <h2 className="text-sm font-display font-semibold text-sentinel-text-primary mb-2">
              Reset Password
            </h2>
            <p className="text-xs font-mono text-sentinel-text-muted">
              Enter the OTP sent to your email and your new password
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
              <p className="text-sm font-mono text-green-600 font-semibold text-center mb-2">
                Password Reset Successfully!
              </p>
              <p className="text-xs font-mono text-sentinel-text-muted text-center">
                Redirecting to login page...
              </p>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
                Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="your.email@example.com"
                className="w-full px-3 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
              />
            </div>

            {/* OTP */}
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-3 text-center">
                OTP Code
              </label>
              <OTPInput
                length={6}
                value={otp}
                onChange={setOtp}
                autoFocus
              />
            </div>

            {/* New Password */}
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
                New Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password (min 6 characters)"
                  className="w-full pl-10 pr-10 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
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
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-text-muted" />
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter new password"
                  className="w-full pl-10 pr-10 py-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40 transition-colors"
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

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded bg-black text-white text-xs font-mono font-semibold hover:bg-gray-800 disabled:opacity-30 transition-colors"
            >
              <KeyRound className="w-3.5 h-3.5" />
              {loading ? 'RESETTING...' : 'RESET PASSWORD'}
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

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-sentinel-bg-primary">
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
              <Link
                href="/login"
                className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
              >
                Login
              </Link>
            </div>
          </div>
        </header>
        <div className="flex items-center justify-center min-h-[calc(100vh-73px)]">
          <div className="sentinel-card w-full max-w-sm p-8">
            <div className="flex items-center justify-center">
              <div className="w-6 h-6 border-2 border-sentinel-accent border-t-transparent rounded-full animate-spin" />
            </div>
          </div>
        </div>
      </div>
    }>
      <ResetPasswordForm />
    </Suspense>
  );
}
