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

/** Parse a composer.json (PHP) — same shape as package.json. */
function parseComposerJson(filePath, deps) {
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return;
  }
  for (const section of ['require', 'require-dev']) {
    const obj = pkg[section];
    if (!obj || typeof obj !== 'object') continue;
    for (const [name, range] of Object.entries(obj)) {
      // Skip reserved Packagist keys (php itself, ext-*, lib-*) — they are
      // runtime requirements, not packages, and would produce noisy CVE lookups.
      if (name === 'php' || name.startsWith('ext-') || name.startsWith('lib-')) continue;
      pushDep(deps, name, range, 'packagist', 'composer.json', section);
    }
  }
}

/** Parse a requirements.txt-style pip requirements file (incl. req.txt). */
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

/** Parse a build.gradle / build.gradle.kts: implementation 'group:artifact:version'. */
function parseGradle(filePath, deps) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }
  const re =
    /\b(?:implementation|api|compile|classpath|kapt|annotationProcessor|runtimeOnly|compileOnly|testImplementation)\s*(?:\(\s*)?['"]([^:]+):([^:]+):([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    pushDep(deps, `${m[1]}:${m[2]}`, m[3], 'maven', path.basename(filePath), null);
  }
}

/** Parse a Maven pom.xml: groupId/artifactId/version dependency blocks. */
function parsePom(filePath, deps) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }
  // Anchored on <dependency> so <parent> blocks (which also carry
  // groupId/artifactId/version) are not mistaken for dependencies.
  const re =
    /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    pushDep(deps, `${m[1]}:${m[2]}`, m[3], 'maven', path.basename(filePath), null);
  }
}

/** Parse a go.mod: single-line and block requires. */
function parseGoMod(filePath, deps) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }
  const chunks = [];
  const blockRe = /require\s*\(([\s\S]*?)\)/g;
  let m;
  while ((m = blockRe.exec(content)) !== null) chunks.push(m[1]);
  const singleRe = /^require\s+(.+)$/gm;
  while ((m = singleRe.exec(content)) !== null) chunks.push(m[1]);
  const depRe = /([A-Za-z0-9_.\-/]+)\s+(v?[0-9][A-Za-z0-9.+\-]*)/g;
  for (const chunk of chunks) {
    while ((m = depRe.exec(chunk)) !== null) {
      pushDep(deps, m[1], m[2], 'go', 'go.mod', null);
    }
  }
}

/** Parse a Ruby Gemfile: gem 'name', 'version'. */
function parseGemfile(filePath, deps) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }
  const re = /\bgem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    pushDep(deps, m[1], m[2], 'rubygems', 'Gemfile', null);
  }
}

/** Parse a Cargo.toml: dependencies sections (skip [package] metadata). */
function parseCargoToml(filePath, deps) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }
  let section = null;
  const depRe = /^\s*([A-Za-z0-9_-]+)\s*=\s*(?:\{\s*version\s*=\s*"([^"]+)"|"([0-9][^"]*)")/;
  for (const line of content.split('\n')) {
    const header = line.match(/^\s*\[([^\]]+)\]/);
    if (header) {
      section = header[1].toLowerCase();
      continue;
    }
    if (!section || !section.includes('dependencies')) continue;
    const m = line.match(depRe);
    // Guard: a bare `version = "1.0"` line under a [dependencies.foo]
    // inline-table section would otherwise be captured as a dep named "version".
    if (m && m[1] !== 'version') pushDep(deps, m[1], m[2] || m[3], 'cargo', 'Cargo.toml', section);
  }
}

/**
 * Walk a repo and extract every dependency with a pinned version.
 * Returns a deduplicated list: [{ name, version, ecosystem, source, section, range }].
 *
 * Manifests are picked up ANYWHERE in the tree (not just the root) so monorepos
 * and apps with their manifest under src/ (e.g. payatu/DVAPI) get proper CVE
 * coverage instead of a silent "no dependencies" false negative. Supported:
 * package.json, composer.json, requirements*.txt / req.txt, build.gradle(kts),
 * pom.xml, go.mod, Gemfile, Cargo.toml.
 */
export function extractDependencies(root) {
  const deps = [];
  const rootPkg = path.join(root, 'package.json');
  if (fs.existsSync(rootPkg)) parsePackageJson(rootPkg, deps);

  for (const file of walkFiles(root)) {
    const n = file.name.toLowerCase();
    if (file.name === 'package.json') {
      // Root manifest already parsed above — avoid double-add.
      if (path.resolve(file.full) === path.resolve(rootPkg)) continue;
      parsePackageJson(file.full, deps);
    } else if (n === 'composer.json') {
      parseComposerJson(file.full, deps);
    } else if (n === 'go.mod') {
      parseGoMod(file.full, deps);
    } else if (file.name === 'Gemfile') {
      parseGemfile(file.full, deps);
    } else if (n === 'build.gradle' || n === 'build.gradle.kts') {
      parseGradle(file.full, deps);
    } else if (n === 'pom.xml') {
      parsePom(file.full, deps);
    } else if (n === 'cargo.toml') {
      parseCargoToml(file.full, deps);
    } else if (n.startsWith('requirements') || n === 'req.txt') {
      parseRequirementsFile(file.full, deps);
    }
  }

  // Dedupe by ecosystem+name — keep the first occurrence.
  const seen = new Set();
  return deps.filter((d) => {
    const key = `${d.ecosystem}:${d.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
