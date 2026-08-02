import fs from 'node:fs';
import path from 'node:path';
import { walkFiles } from '../util.js';

/** Strip range operators ("^1.2.3", "~=2.0", ">=1.0,<2.0") down to a concrete-looking version. */
export function cleanVersion(range) {
  if (!range || typeof range !== 'string') return null;
  const r = range.trim().replace(/[()]/g, '');
  if (!r || r === '*' || r === 'latest') return null;
  const m = r.match(/\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?/);
  return m ? m[0] : null;
}

function pushDep(list, name, range, ecosystem, source, section) {
  if (!name || typeof name !== 'string') return;
  const version = cleanVersion(range);
  if (!version) return;
  list.push({ name: name.trim(), version, ecosystem, source, section, range });
}

/** Read a package.json and collect its dependency sections. */
function parsePackageJson(filePath, deps) {
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return;
  }
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const obj = pkg[section];
    if (!obj || typeof obj !== 'object') continue;
    for (const [name, range] of Object.entries(obj)) {
      pushDep(deps, name, range, 'npm', 'package.json', section);
    }
  }
}

/** Parse a requirements.txt (or similar pip requirements file). */
function parseRequirementsFile(filePath, deps) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }
  for (const rawLine of content.split('\n')) {
    const line = rawLine.replace(/\s*#.*$/, '').trim(); // strip comments
    if (!line) continue;
    if (line.startsWith('-') || line.startsWith('--')) continue; // -r, -e, --index-url etc.
    if (line.includes('://')) continue; // VCS / direct URL deps — skip
    // Split on the first version operator
    const m = line.match(/^([A-Za-z0-9_.\-]+)\s*(?:===|==|>=|<=|~=|!=|>|<)\s*(.+)$/);
    if (m) {
      pushDep(deps, m[1], m[2], 'pypi', path.basename(filePath), null);
    }
  }
}

/**
 * Walk a repo and extract every dependency with a pinned version.
 * Returns a deduplicated list: [{ name, version, ecosystem, source, section, range }].
 */
export function extractDependencies(root) {
  const deps = [];
  const rootPkg = path.join(root, 'package.json');
  if (fs.existsSync(rootPkg)) parsePackageJson(rootPkg, deps);

  // requirements files anywhere in the tree (usually at root)
  for (const file of walkFiles(root)) {
    if (
      file.name === 'requirements.txt' ||
      file.name === 'requirements-dev.txt' ||
      file.name === 'requirements-prod.txt'
    ) {
      parseRequirementsFile(file.full, deps);
    }
  }

  // Dedupe by name — keep the first occurrence (production deps win over devDeps).
  const seen = new Set();
  return deps.filter((d) => {
    const key = `${d.ecosystem}:${d.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
