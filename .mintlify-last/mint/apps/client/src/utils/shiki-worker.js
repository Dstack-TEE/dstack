import { expose } from 'comlink';

const THEMES = ['dark-plus', 'github-light-default'];
const LANGS = [
  'bash',
  'blade',
  'c',
  'c#',
  'c++',
  'dart',
  'go',
  'java',
  'javascript',
  'jsx',
  'json',
  'kotlin',
  'markdown',
  'php',
  'python',
  'ruby',
  'swift',
  'typescript',
  'tsx',
  'yaml',
];

const shikiColorReplacements = {
  [THEMES[0]]: {
    '#1e1e1e': 'transparent',
    '#569cd6': '#9cdcfe',
    '#c8c8c8': '#f3f7f6',
    '#d4d4d4': '#f3f7f6',
  },
  [THEMES[1]]: { '#fff': 'transparent', '#ffffff': 'transparent' },
};

const shikiThemeMap = { dark: THEMES[0], light: THEMES[1] };

const shikiLangMap = {
  curl: 'bash',
  bash: 'bash',
  sh: 'bash',
  shell: 'bash',
  zsh: 'bash',
  c: 'c',
  'c#': 'c#',
  csharp: 'c#',
  cs: 'c#',
  'c++': 'c++',
  cpp: 'c++',
  cc: 'c++',
  go: 'go',
  golang: 'go',
  java: 'java',
  javascript: 'javascript',
  js: 'javascript',
  jsx: 'jsx',
  reactjs: 'jsx',
  'react-js': 'jsx',
  json: 'json',
  jsonc: 'json',
  json5: 'json',
  php: 'php',
  blade: 'blade',
  python: 'python',
  py: 'python',
  typescript: 'typescript',
  ts: 'typescript',
  tsx: 'tsx',
  react: 'tsx',
  reactts: 'tsx',
  'react-ts': 'tsx',
  ruby: 'ruby',
  rb: 'ruby',
  swift: 'swift',
  kotlin: 'kotlin',
  kt: 'kotlin',
  dart: 'dart',
  flutter: 'dart',
  markdown: 'markdown',
  md: 'markdown',
  mdx: 'markdown',
  yaml: 'yaml',
  yml: 'yaml',
  toml: 'yaml',
};

let highlighter;
let hastToHtmlFn;

const ready = (async () => {
  const { createHighlighter, hastToHtml, createJavaScriptRegexEngine } = await import('shiki');
  hastToHtmlFn = hastToHtml;
  const engine = createJavaScriptRegexEngine({ forgiving: true, cache: new Map() });
  highlighter = await createHighlighter({ themes: THEMES, langs: LANGS, engine });
})();

function getShikiLanguage(lang) {
  const text = 'text';
  const n = Number(lang);
  const isStatus = !Number.isNaN(n) && Number.isFinite(n) && n > 99 && n < 600;
  return isStatus ? 'json' : lang ? shikiLangMap[lang.toLowerCase()] ?? text : text;
}

function getLanguageFromClassName(className, fallback) {
  const m = /language-(\w+)/.exec(className ?? '');
  return m ? m[1] ?? 'text' : fallback ?? 'text';
}

function highlightSync(opts) {
  let lang =
    'language' in opts ? opts.language : getLanguageFromClassName(opts.className, opts.fileName);
  let html = undefined;
  if (lang) {
    const serializer = opts.opts?.highlightedLines ? 'codeToHast' : 'codeToHtml';
    const code = opts.codeString.trim();
    html = highlighter[serializer](code, {
      lang: getShikiLanguage(lang),
      themes: {
        dark: shikiThemeMap.dark,
        light: opts.codeBlockTheme !== 'system' ? shikiThemeMap.dark : shikiThemeMap.light,
      },
      colorReplacements: { ...shikiColorReplacements },
      ...opts.opts,
    });
  }
  if (typeof html !== 'object') return html;
  const pre = html.children[0];
  if (pre?.type === 'element' && pre.tagName === 'pre') {
    pre.children[0].children.forEach((c, i) => {
      if (
        opts.opts?.highlightedLines?.includes(i) &&
        c.type === 'element' &&
        c.tagName === 'span' &&
        typeof c.properties.class === 'string'
      )
        c.properties.class += ' line-highlight';
    });
  }
  return hastToHtmlFn(html);
}

async function highlight(props) {
  await ready;
  return highlightSync(props);
}

expose({ highlight, ready });
