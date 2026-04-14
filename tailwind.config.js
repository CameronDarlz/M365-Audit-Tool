/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#080d18',
        surface: '#0f172a',
        card: '#162032',
        border: '#1e3a5f',
        blue: {
          DEFAULT: '#38bdf8',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
        },
        green: {
          DEFAULT: '#34d399',
          400: '#34d399',
        },
        yellow: {
          DEFAULT: '#fbbf24',
          400: '#fbbf24',
        },
        orange: {
          DEFAULT: '#fb923c',
          400: '#fb923c',
        },
        red: {
          DEFAULT: '#f87171',
          400: '#f87171',
        },
        text: '#e2e8f0',
        muted: '#94a3b8',
      },
      fontFamily: {
        sans: ['DM Sans', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
};


