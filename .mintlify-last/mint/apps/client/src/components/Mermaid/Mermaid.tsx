'use client';

import mermaid, { MermaidConfig } from 'mermaid';
import { ReactElement, useCallback, useEffect, useId, useRef, useState } from 'react';

import { Classes } from '@/lib/local/selectors';

export function Mermaid({ chart }: { chart: string }): ReactElement {
  const id = useId();
  const [svg, setSvg] = useState('');
  const containerRef = useRef<HTMLDivElement | null>(null);
  const htmlElement = document.documentElement;
  const [isDarkTheme, setIsDarkTheme] = useState(() =>
    document.documentElement.classList.contains('dark')
  );

  const renderChart = useCallback(async () => {
    const mermaidConfig: MermaidConfig = {
      startOnLoad: false,
      fontFamily: 'inherit',
      theme: isDarkTheme ? 'dark' : 'default',
    };

    try {
      mermaid.initialize(mermaidConfig);

      const { svg } = await mermaid.render(
        // Strip invalid characters for `id` attribute.
        id.replaceAll(':', ''),
        chart,
        containerRef.current || undefined
      );

      setSvg(svg);
    } catch (error) {
      console.error('Error while rendering mermaid', error);
    }
  }, [chart, id, isDarkTheme]);

  useEffect(() => {
    const mutationObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        const classList = (mutation.target as HTMLElement).classList;
        const darkMode = classList.contains('dark');
        if (darkMode !== isDarkTheme) {
          setIsDarkTheme(darkMode);
        }
      }
    });
    mutationObserver.observe(htmlElement, { attributes: true, attributeFilter: ['class'] });

    renderChart().catch((error) => {
      console.error('Error while rendering mermaid', error);
    });

    return () => {
      mutationObserver.disconnect();
    };
  }, [htmlElement, isDarkTheme, renderChart]);

  return (
    <div ref={containerRef} dangerouslySetInnerHTML={{ __html: svg }} className={Classes.Mermaid} />
  );
}
