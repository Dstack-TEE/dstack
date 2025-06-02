import 'focus-visible';
import type { AppProps } from 'next/app';
import { Inter, JetBrains_Mono } from 'next/font/google';

import ErrorBoundary from '@/ui/ErrorBoundary';

import '../css/main.css';

const inter = Inter({
  display: 'block',
  subsets: ['latin'],
  variable: '--font-inter',
});
const jetbrainsMono = JetBrains_Mono({
  display: 'swap',
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
});

export default function App(props: AppProps) {
  const { Component, pageProps } = props;

  return (
    <ErrorBoundary>
      <style jsx global>{`
        :root {
          --font-inter: ${inter.style.fontFamily};
          --font-jetbrains-mono: ${jetbrainsMono.style.fontFamily};
        }
      `}</style>
      <main>
        <Component {...pageProps} />
      </main>
    </ErrorBoundary>
  );
}
