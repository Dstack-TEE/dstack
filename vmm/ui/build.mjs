// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

import fs from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';
import { createRequire } from 'module';

const ROOT = path.resolve(new URL('.', import.meta.url).pathname);
const SOURCE_DIR = path.join(ROOT, 'src');
const TS_OUT_DIR = path.join(ROOT, 'build', 'ts');
const DIST_DIR = path.join(ROOT, 'dist');
const ENTRY = 'main.js';
const PBJS = path.join(ROOT, 'node_modules', '.bin', process.platform === 'win32' ? 'pbjs.cmd' : 'pbjs');
const PBTS = path.join(ROOT, 'node_modules', '.bin', process.platform === 'win32' ? 'pbts.cmd' : 'pbts');
const TSC = path.join(ROOT, 'node_modules', '.bin', process.platform === 'win32' ? 'tsc.cmd' : 'tsc');
let MODULE_DIR = TS_OUT_DIR;
const nodeRequire = createRequire(path.join(ROOT, 'package.json'));

function canonicalId(absPath) {
  return path.relative(ROOT, absPath).split(path.sep).join('/');
}

function resolveModule(parentId, request) {
  const base = parentId ? path.dirname(path.resolve(ROOT, parentId)) : MODULE_DIR;
  const absPath = nodeRequire.resolve(request, { paths: [base] });
  return canonicalId(absPath);
}

async function readFileCached(filePath) {
  return fs.readFile(filePath, 'utf-8');
}

async function collectModules(entryId) {
  const modules = new Map();

  async function processModule(moduleId) {
    if (modules.has(moduleId)) {
      return;
    }
    const absPath = path.resolve(ROOT, moduleId);
    const ext = path.extname(absPath);
    if (ext === '.html') {
      const content = await readFileCached(absPath);
      modules.set(moduleId, {
        type: 'raw',
        code: `module.exports = ${JSON.stringify(content)};`,
        dependencyMap: {},
      });
      return;
    }
    if (ext === '.json') {
      const content = await readFileCached(absPath);
      modules.set(moduleId, {
        type: 'raw',
        code: `module.exports = ${content};`,
        dependencyMap: {},
      });
      return;
    }
    if (ext !== '.js' && ext !== '.cjs' && ext !== '.mjs') {
      throw new Error(`Unsupported module extension: ${absPath}`);
    }
    const source = await readFileCached(absPath);
    const dependencyMap = {};
    const requireRegex = /require\(['"](.+?)['"]\)/g;
    let match;
    while ((match = requireRegex.exec(source)) !== null) {
      const lineStart = source.lastIndexOf('\n', match.index) + 1;
      const trimmed = source.slice(lineStart, match.index).trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) {
        continue;
      }
      const request = match[1];
      const resolved = resolveModule(moduleId, request);
      dependencyMap[request] = resolved;
    }
    const dependencies = Array.from(new Set(Object.values(dependencyMap)));
    modules.set(moduleId, {
      type: 'js',
      code: source,
      dependencyMap,
      dependencies,
    });
    for (const dep of dependencies) {
      await processModule(dep);
    }
  }

  await processModule(entryId);
  return modules;
}

function createBundle(modules, entryId) {
  const moduleEntries = [];
  for (const [id, info] of modules.entries()) {
    const deps = JSON.stringify(info.dependencyMap || {});
    moduleEntries.push(
      `'${id}': { factory: function(module, exports, require) {\n${info.code}\n}, map: ${deps} }`,
    );
  }
  return `(function(){\n  const modules = {\n${moduleEntries.join(',\n')}\n  };\n  const cache = {};\n  function load(id) {\n    if (cache[id]) {\n      return cache[id];\n    }\n    const entry = modules[id];\n    if (!entry) {\n      throw new Error('Unknown module ' + id);\n    }\n    const module = { exports: {} };\n    cache[id] = module.exports;\n    entry.factory(module, module.exports, createRequire(id));\n    cache[id] = module.exports;\n    return cache[id];\n  }\n  function createRequire(parentId) {\n    return function(request) {\n      const parent = modules[parentId];\n      if (!parent) {\n        throw new Error('Unknown parent module ' + parentId);\n      }\n      const resolved = parent.map && parent.map[request];\n      if (!resolved) {\n        throw new Error('Cannot resolve module ' + request + ' from ' + parentId);\n      }\n      return load(resolved);\n    };\n  }\n  load('${entryId}');\n})();`;
}

async function inlineStyles(html, baseDir) {
  const linkRegex = /<link\s+rel=["']stylesheet["']\s+href=["'](.+?)["']\s*\/?>(?:\s*<\/link>)?/gi;
  let result = html;
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    const href = match[1];
    const cssPath = path.resolve(baseDir, href);
    const cssContent = await fs.readFile(cssPath, 'utf-8');
    const styleTag = `<style>\n${cssContent}\n</style>`;
    result = result.replace(match[0], styleTag);
  }
  return result;
}

async function inlineScripts(html, scripts) {
  let result = html;
  for (const { placeholder, code } of scripts) {
    result = result.replace(placeholder, `<script>\n${code}\n</script>`);
  }
  return result;
}

async function run(command, args) {
  await new Promise((resolve, reject) => {
    const proc = spawn(command, args, { stdio: 'inherit' });
    proc.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} exited with code ${code}`));
      }
    });
  });
}

async function copyDir(src, dest) {
  const entries = await fs.readdir(src, { withFileTypes: true });
  await fs.mkdir(dest, { recursive: true });
  await Promise.all(
    entries.map((entry) => {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);
      if (entry.isDirectory()) {
        return copyDir(srcPath, destPath);
      }
      return fs.copyFile(srcPath, destPath);
    }),
  );
}

async function compileProto() {
  await run('bash', [path.join(ROOT, 'scripts', 'build_proto.sh')]);
}

async function compileTypeScript() {
  await fs.rm(TS_OUT_DIR, { recursive: true, force: true });
  await run(TSC, ['--project', path.join(ROOT, 'tsconfig.json')]);
  await copyDir(path.join(SOURCE_DIR, 'templates'), path.join(TS_OUT_DIR, 'templates'));
}

async function build({ watch = false } = {}) {
  await fs.mkdir(DIST_DIR, { recursive: true });
  MODULE_DIR = TS_OUT_DIR;

  await compileProto();
  await compileTypeScript();

  const entryId = canonicalId(path.resolve(MODULE_DIR, ENTRY));
  const modules = await collectModules(entryId);
  const bundle = createBundle(modules, entryId);

  const indexPath = path.join(SOURCE_DIR, 'index.html');
  let html = await fs.readFile(indexPath, 'utf-8');
  html = await inlineStyles(html, SOURCE_DIR);

  const vuePlaceholder = /<script\s+src=["']\.\.\/vendor\/vue\.global\.prod\.js["']><\/script>/i;
  const vuePath = path.join(ROOT, 'vendor/vue.global.prod.js');
  let vueInlined = false;
  try {
    const vueCode = await fs.readFile(vuePath, 'utf-8');
    html = html.replace(vuePlaceholder, `<script>\n${vueCode}\n</script>`);
    vueInlined = true;
  } catch {
    console.warn('Warning: vendor/vue.global.prod.js not found – using CDN fallback.');
  }
  if (!vueInlined) {
    html = html.replace(
      vuePlaceholder,
      '<script src="https://unpkg.com/vue@3.4.21/dist/vue.global.prod.js"></script>',
    );
  }

  html = await inlineScripts(html, [
    {
      placeholder: '<script src="./main.js"></script>',
      code: bundle,
    },
  ]);

  const distFile = path.join(DIST_DIR, 'index.html');
  await fs.writeFile(distFile, html);

  const targetFile = path.resolve(ROOT, '../src/console_v1.html');
  await fs.writeFile(targetFile, html);

  if (watch) {
    console.log('Watching for changes...');
    const watcher = fs.watch(SOURCE_DIR, { recursive: true }, async () => {
      try {
        await compileProto();
        await compileTypeScript();
        const mods = await collectModules(entryId);
        const rebundle = createBundle(mods, entryId);
        let rehtml = await fs.readFile(indexPath, 'utf-8');
        rehtml = await inlineStyles(rehtml, SOURCE_DIR);
        let vueEmbedded = false;
        try {
          const vueCode = await fs.readFile(vuePath, 'utf-8');
          rehtml = rehtml.replace(vuePlaceholder, `<script>\n${vueCode}\n</script>`);
          vueEmbedded = true;
        } catch {
          console.warn('Warning: vendor/vue.global.prod.js not found – using CDN fallback.');
        }
        if (!vueEmbedded) {
          rehtml = rehtml.replace(
            vuePlaceholder,
            '<script src="https://unpkg.com/vue@3.4.21/dist/vue.global.prod.js"></script>',
          );
        }
        rehtml = await inlineScripts(rehtml, [
          {
            placeholder: '<script src="./main.js"></script>',
            code: rebundle,
          },
        ]);
        await fs.writeFile(distFile, rehtml);
        const spdxHeader = '<!-- SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>\n     SPDX-License-Identifier: Apache-2.0 -->\n';
        await fs.writeFile(targetFile, spdxHeader + rehtml);
        console.log('Rebuilt console');
      } catch (err) {
        console.error('Build failed:', err);
      }
    });
    process.on('SIGINT', () => watcher.close());
  }
}

const watchMode = process.argv.includes('--watch');

build({ watch: watchMode }).catch((error) => {
  console.error(error);
  process.exit(1);
});
