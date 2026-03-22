'use client';

import { useState } from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import { ArrowLeft, Bug, Database, Lightbulb, AlertTriangle, Mail, User, MessageSquare, Shield, CheckCircle, LogOut } from 'lucide-react';
import { useAuth } from '@/lib/auth';

// Note: Metadata export is commented out because this is a client component
// To use metadata, you'd need to create a separate layout.tsx or make this a server component
// export const metadata: Metadata = {
//   title: 'Contact Wiestell | Threat Intelligence Platform',
//   description: 'Get in touch with the Wiestell team for feed issues, API access, feature requests, or abuse reports.',
// };

type ReasonType = 'feed-issue' | 'api-access' | 'feature-request' | 'abuse-report' | '';

interface ReasonCard {
  id: ReasonType;
  icon: React.ElementType;
  title: string;
  description: string;
}

interface FormData {
  name: string;
  email: string;
  reason: ReasonType;
  ioc: string;
  message: string;
}

interface FormErrors {
  name?: string;
  email?: string;
  reason?: string;
  message?: string;
}

const reasonCards: ReasonCard[] = [
  {
    id: 'feed-issue',
    icon: Database,
    title: 'Feed Issue / False Positive',
    description: 'Think a result is incorrect, a legitimate IP is flagged, or a feed is returning stale data? Let us know so we can investigate and improve accuracy.',
  },
  {
    id: 'api-access',
    icon: Shield,
    title: 'API Access /Integration',
    description: 'Interested in integrating Wiestell into your SIEM, SOAR, or custom tooling? Get in touch to discuss API access options.',
  },
  {
    id: 'feature-request',
    icon: Lightbulb,
    title: 'Feature Request',
    description: 'Have an idea for a new feature, feed integration, or search type (e.g. ASN lookup, YARA rules, CVE correlation)? We want to hear it.',
  },
  {
    id: 'abuse-report',
    icon: AlertTriangle,
    title: 'Abuse Report',
    description: 'If Wiestell is being used to target you or your infrastructure, or if your IP/domain has been wrongly listed, report it here.',
  },
];

export default function ContactPage() {
  const router = useRouter();
  const { user, logout } = useAuth();
  
  const [formData, setFormData] = useState<FormData>({
    name: '',
    email: '',
    reason: '',
    ioc: '',
    message: '',
  });

  const [errors, setErrors] = useState<FormErrors>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validateForm = (): boolean => {
    const newErrors: FormErrors = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
    }

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!validateEmail(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    if (!formData.reason) {
      newErrors.reason = 'Please select a reason';
    }

    if (!formData.message.trim()) {
      newErrors.message = 'Message is required';
    } else if (formData.message.trim().length < 20) {
      newErrors.message = 'Message must be at least 20 characters';
    } else if (formData.message.trim().length > 1000) {
      newErrors.message = 'Message must not exceed 1000 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);

    try {
      // Call the backend API to submit the contact form
      const response = await fetch('/api/v1/contact/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        throw new Error('Failed to submit contact form');
      }

      const result = await response.json();
      console.log('Contact submitted:', result);

      setIsSuccess(true);
      
      // Store email for display in success message
      const submittedEmail = formData.email;
      
      // Reset form
      setFormData({
        name: '',
        email: submittedEmail, // Keep email for success message display
        reason: '',
        ioc: '',
        message: '',
      });
    } catch (error) {
      console.error('Error submitting form:', error);
      setErrors({ message: 'Failed to send message. Please try again.' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReasonSelect = (reasonId: ReasonType) => {
    setFormData({ ...formData, reason: reasonId });
    if (errors.reason) {
      setErrors({ ...errors, reason: undefined });
    }
  };

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
    
    // Clear error for this field when user starts typing
    if (errors[name as keyof FormErrors]) {
      setErrors({ ...errors, [name]: undefined });
    }
  };

  if (isSuccess) {
    return (
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
                className="px-4 py-2 text-sm font-mono text-sentinel-accent hover:text-sentinel-accent transition-colors font-semibold"
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

        <main className="container mx-auto px-6 py-12">
          <div className="max-w-2xl mx-auto">
            <div className="sentinel-card p-10 text-center">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-sentinel-bg-secondary mb-6">
                <CheckCircle className="w-8 h-8 text-sentinel-accent" />
              </div>
              <h1 className="text-3xl font-display font-bold text-sentinel-text-primary mb-4">
                Message Sent Successfully
              </h1>
              <p className="text-sentinel-text-secondary font-mono text-sm mb-8 leading-relaxed">
                Thank you for reaching out. We have received your message and will respond within 2 business days. Our team will review your inquiry and get back to you at <strong className="text-sentinel-accent">{formData.email || 'the provided email address'}</strong>.
              </p>
              <div className="flex gap-4 justify-center">
                <button
                  onClick={() => setIsSuccess(false)}
                  className="px-6 py-3 bg-sentinel-accent text-white font-mono text-sm rounded hover:bg-sentinel-accent-secondary transition-colors"
                >
                  Send Another Message
                </button>
                <Link
                  href="/"
                  className="px-6 py-3 border border-sentinel-border text-sentinel-text-primary font-mono text-sm rounded hover:bg-sentinel-bg-secondary transition-colors"
                >
                  Return to Home
                </Link>
              </div>
            </div>
          </div>
        </main>
      </div>
    );
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
              className="px-4 py-2 text-sm font-mono text-sentinel-accent hover:text-sentinel-accent transition-colors font-semibold"
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
      <main className="container mx-auto px-6 py-12">
        <div className="max-w-4xl mx-auto">
          {/* Page Header */}
          <div className="text-center mb-12">
            <h1 className="text-4xl md:text-5xl font-display font-bold text-sentinel-text-primary mb-4">
              Contact Wiestell
            </h1>
            <p className="text-sentinel-text-secondary font-mono text-sm max-w-2xl mx-auto leading-relaxed">
              Have a question about Wiestell? Found a bug? Want to suggest a new threat intelligence feed? We'd like to hear from you. Use the options below to get in touch.
            </p>
          </div>

          {/* Reason Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-10">
            {reasonCards.map((card) => {
              const Icon = card.icon;
              const isSelected = formData.reason === card.id;
              
              return (
                <button
                  key={card.id}
                  type="button"
                  onClick={() => handleReasonSelect(card.id)}
                  className={`
                    sentinel-card p-6 text-left transition-all duration-200
                    ${
                      isSelected
                        ? 'border-2 border-sentinel-accent bg-sentinel-bg-secondary'
                        : 'border border-sentinel-border hover:border-sentinel-border-hover hover:bg-sentinel-bg-secondary/50'
                    }
                  `}
                >
                  <div className="flex items-start gap-4">
                    <div className={`
                      p-3 rounded-lg transition-colors
                      ${isSelected ? 'bg-sentinel-accent' : 'bg-sentinel-bg-secondary'}
                    `}>
                      <Icon className={`w-6 h-6 ${isSelected ? 'text-white' : 'text-sentinel-accent'}`} />
                    </div>
                    <div className="flex-1">
                      <h3 className="text-lg font-display font-semibold text-sentinel-text-primary mb-2">
                        {card.title}
                      </h3>
                      <p className="text-sm font-mono text-sentinel-text-secondary leading-relaxed">
                        {card.description}
                      </p>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {errors.reason && (
            <p className="text-sm font-mono text-sentinel-danger mb-6 text-center">
              {errors.reason}
            </p>
          )}

          {/* Contact Form */}
          <div className="sentinel-card p-8">
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Name Field */}
              <div>
                <label htmlFor="name" className="block text-sm font-mono font-semibold text-sentinel-text-primary mb-2">
                  Name <span className="text-sentinel-danger">*</span>
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-sentinel-text-muted" />
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    className={`
                      w-full pl-11 pr-4 py-3 rounded border font-mono text-sm
                      bg-sentinel-bg-primary text-sentinel-text-primary
                      focus:outline-none focus:ring-2 focus:ring-sentinel-accent
                      ${errors.name ? 'border-sentinel-danger' : 'border-sentinel-border'}
                    `}
                    placeholder="Your full name"
                  />
                </div>
                {errors.name && (
                  <p className="mt-1 text-xs font-mono text-sentinel-danger">{errors.name}</p>
                )}
              </div>

              {/* Email Field */}
              <div>
                <label htmlFor="email" className="block text-sm font-mono font-semibold text-sentinel-text-primary mb-2">
                  Email <span className="text-sentinel-danger">*</span>
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-sentinel-text-muted" />
                  <input
                    type="email"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    className={`
                      w-full pl-11 pr-4 py-3 rounded border font-mono text-sm
                      bg-sentinel-bg-primary text-sentinel-text-primary
                      focus:outline-none focus:ring-2 focus:ring-sentinel-accent
                      ${errors.email ? 'border-sentinel-danger' : 'border-sentinel-border'}
                    `}
                    placeholder="your.email@example.com"
                  />
                </div>
                {errors.email && (
                  <p className="mt-1 text-xs font-mono text-sentinel-danger">{errors.email}</p>
                )}
              </div>

              {/* Reason Dropdown */}
              <div>
                <label htmlFor="reason" className="block text-sm font-mono font-semibold text-sentinel-text-primary mb-2">
                  Reason <span className="text-sentinel-danger">*</span>
                </label>
                <select
                  id="reason"
                  name="reason"
                  value={formData.reason}
                  onChange={(e) => {
                    setFormData({ ...formData, reason: e.target.value as ReasonType });
                    if (errors.reason) {
                      setErrors({ ...errors, reason: undefined });
                    }
                  }}
                  className={`
                    w-full px-4 py-3 rounded border font-mono text-sm
                    bg-sentinel-bg-primary text-sentinel-text-primary
                    focus:outline-none focus:ring-2 focus:ring-sentinel-accent
                    ${errors.reason ? 'border-sentinel-danger' : 'border-sentinel-border'}
                  `}
                >
                  <option value="">Select a reason</option>
                  <option value="feed-issue">Feed Issue</option>
                  <option value="api-access">API Access</option>
                  <option value="feature-request">Feature Request</option>
                  <option value="abuse-report">Abuse Report</option>
                </select>
                {errors.reason && (
                  <p className="mt-1 text-xs font-mono text-sentinel-danger">{errors.reason}</p>
                )}
              </div>

              {/* IOC/Indicator Field (Optional) */}
              <div>
                <label htmlFor="ioc" className="block text-sm font-mono font-semibold text-sentinel-text-primary mb-2">
                  IOC / Indicator <span className="text-sentinel-text-muted">(Optional)</span>
                </label>
                <input
                  type="text"
                  id="ioc"
                  name="ioc"
                  value={formData.ioc}
                  onChange={handleInputChange}
                  className="w-full px-4 py-3 rounded border border-sentinel-border font-mono text-sm bg-sentinel-bg-primary text-sentinel-text-primary focus:outline-none focus:ring-2 focus:ring-sentinel-accent"
                  placeholder="e.g., 192.168.1.1, example.com, hash..."
                />
                <p className="mt-1 text-xs font-mono text-sentinel-text-muted">
                  If reporting about a specific IOC, include it here
                </p>
              </div>

              {/* Message Field */}
              <div>
                <label htmlFor="message" className="block text-sm font-mono font-semibold text-sentinel-text-primary mb-2">
                  Message <span className="text-sentinel-danger">*</span>
                </label>
                <div className="relative">
                  <MessageSquare className="absolute left-3 top-3 w-5 h-5 text-sentinel-text-muted" />
                  <textarea
                    id="message"
                    name="message"
                    value={formData.message}
                    onChange={handleInputChange}
                    rows={6}
                    className={`
                      w-full pl-11 pr-4 py-3 rounded border font-mono text-sm
                      bg-sentinel-bg-primary text-sentinel-text-primary
                      focus:outline-none focus:ring-2 focus:ring-sentinel-accent resize-none
                      ${errors.message ? 'border-sentinel-danger' : 'border-sentinel-border'}
                    `}
                    placeholder="Describe your inquiry in detail (20-1000 characters)..."
                  />
                </div>
                <div className="flex justify-between items-center mt-1">
                  {errors.message ? (
                    <p className="text-xs font-mono text-sentinel-danger">{errors.message}</p>
                  ) : (
                    <p className="text-xs font-mono text-sentinel-text-muted">
                      Minimum 20 characters required
                    </p>
                  )}
                  <p className="text-xs font-mono text-sentinel-text-muted">
                    {formData.message.length}/1000
                  </p>
                </div>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isSubmitting}
                className={`
                  w-full py-4 px-6 rounded font-mono font-semibold text-sm
                  transition-all duration-200
                  ${
                    isSubmitting
                      ? 'bg-sentinel-text-muted text-white cursor-not-allowed'
                      : 'bg-sentinel-accent text-white hover:bg-sentinel-accent-secondary'
                  }
                `}
              >
                {isSubmitting ? 'Sending...' : 'Send Message'}
              </button>
            </form>
          </div>

          {/* Additional Contact Info */}
          <div className="mt-8 text-center">
            <p className="text-sm font-mono text-sentinel-text-secondary">
              For urgent security issues, please email{' '}
              <a
                href="mailto:security@wiestell.com"
                className="text-sentinel-accent hover:underline font-semibold"
              >
                security@wiestell.com
              </a>
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
