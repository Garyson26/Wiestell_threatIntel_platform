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
          'bg-primary': '#ffffff',
          'bg-secondary': '#f5f5f5',
          'bg-tertiary': '#ebebeb',
          'bg-hover': '#e0e0e0',
          'border': '#d4d4d4',
          'border-hover': '#b3b3b3',
          'accent': '#000000',
          'accent-secondary': '#1a1a1a',
          'warning': '#333333',
          'danger': '#666666',
          'success': '#2a2a2a',
          'text-primary': '#000000',
          'text-secondary': '#4a4a4a',
          'text-muted': '#8c8c8c',
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
