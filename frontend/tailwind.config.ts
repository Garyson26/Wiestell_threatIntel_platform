import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          'bg-primary': '#0a0f1a',
          'bg-secondary': '#111827',
          'bg-tertiary': '#1a2332',
          'bg-hover': '#1e2a3a',
          'border': '#1e293b',
          'border-hover': '#334155',
          'accent': '#00e5ff',
          'accent-secondary': '#7c3aed',
          'warning': '#f59e0b',
          'danger': '#ef4444',
          'success': '#10b981',
          'text-primary': '#e2e8f0',
          'text-secondary': '#94a3b8',
          'text-muted': '#64748b',
        },
      },
      fontFamily: {
        display: ['Space Grotesk', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
        body: ['Space Grotesk', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.5s ease-out forwards',
        'slide-up': 'slideUp 0.3s ease-out forwards',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(16px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};

export default config;
