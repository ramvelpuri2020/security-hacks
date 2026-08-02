import fs from 'node:fs';
import path from 'node:path';

/** File extensions we actually scan. Everything else (binaries, images, etc.) is skipped. */
export const SOURCE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.py', '.rb', '.php', '.go', '.java', '.c', '.h', '.cpp', '.hpp', '.cs',
  '.sh', '.bash', '.zsh', '.ps1',
  '.json', '.yaml', '.yml', '.toml', '.xml', '.ini', '.cfg', '.conf', '.properties',
  '.html', '.htm', '.vue', '.sql', '.env', '.txt', '.md',
  '.gradle', '.lock',
]);

/** Directories that never contain app source worth scanning. */
export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.output',
  '.venv', 'venv', 'env', 'target', 'vendor', '.cache', '.yarn', '.pnp',
  '__pycache__', '.idea', '.vscode', 'coverage', '.terraform', 'site-packages',
  'bower_components', 'Pods', '.tox', 'htmlcov', '.mypy_cache', '.pytest_cache',
]);

/** Individual files larger than this are skipped (usually minified/bundled). */
export const MAX_FILE_BYTES = 512 * 1024;

export function isSkippedDir(name) {
  return SKIP_DIRS.has(name);
}

export function isSourceFile(name) {
  const ext = path.extname(name).toLowerCase();
  if (!SOURCE_EXTENSIONS.has(ext)) return false;
  // Lockfiles are huge and not interesting for secret/injection scanning.
  if (name === 'package-lock.json' || name === 'yarn.lock' || name === 'pnpm-lock.yaml') return false;
  return true;
}

/**
 * Walk a directory tree, yielding { full, rel, name, ext, size } for each
 * scannable source file. Skipped dirs and oversized files are excluded.
 */
export function* walkFiles(root) {
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable dir — skip
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!isSkippedDir(entry.name)) stack.push(full);
      } else if (entry.isFile() && isSourceFile(entry.name)) {
        let size = 0;
        try {
          size = fs.statSync(full).size;
        } catch {
          continue;
        }
        if (size > MAX_FILE_BYTES || size === 0) continue;
        yield {
          full,
          rel: path.relative(root, full).split(path.sep).join('/'),
          name: entry.name,
          ext: path.extname(entry.name).toLowerCase(),
          size,
        };
      }
    }
  }
}

/**
 * Given a byte index into content, return the 1-based line number and the
 * text of that line (trimmed).
 */
export function locateLine(content, index) {
  const upTo = content.slice(0, index);
  const lineNumber = upTo.split('\n').length;
  const lines = content.split('\n');
  const code = (lines[lineNumber - 1] || '').trim().slice(0, 300);
  return { line: lineNumber, code };
}

/** Run a global regex over content and produce structured matches with line info. */
export function collectMatches(content, regex, fileRel) {
  const matches = [];
  let m;
  const g = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
  while ((m = g.exec(content)) !== null) {
    const { line, code } = locateLine(content, m.index);
    matches.push({
      match: m[0].slice(0, 200),
      line,
      code,
      file: fileRel,
    });
    if (m[0].length === 0) g.lastIndex++; // guard against zero-width loops
  }
  return matches;
}
