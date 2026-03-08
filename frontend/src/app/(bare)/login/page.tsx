'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import { LogIn, KeyRound } from 'lucide-react';
import { loginUser, verifyOtp } from '@/lib/api';
import { useAuth } from '@/lib/auth';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [otpStep, setOtpStep] = useState(false);
  const [otpMessage, setOtpMessage] = useState('');
  const router = useRouter();
  const { login } = useAuth();

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
      login(res.access_token, res.user);
      // Redirect to dashboard
      router.push('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Invalid OTP.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex items-center justify-center min-h-[80vh]">
      <div className="sentinel-card w-full max-w-sm p-8 animate-fade-in">
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
          {otpStep ? 'Enter OTP' : 'Sign In'}
        </h2>

        {error && (
          <div className="mb-4 p-2.5 rounded bg-gray-200 border border-gray-300">
            <p className="text-xs font-mono text-gray-700 text-center">{error}</p>
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
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter email"
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
          No account?{' '}
          <button
            onClick={() => router.push('/signup')}
            className="text-sentinel-accent hover:underline"
          >
            Sign up
          </button>
        </p>
      </div>
    </div>
  );
}
