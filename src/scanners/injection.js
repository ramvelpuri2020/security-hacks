import fs from 'node:fs';
import { collectMatches } from '../util.js';

/**
 * Risky-code patterns: SQL string concatenation, eval, unsafe exec,
 * Python subprocess shell=True, pickle deserialization, XSS sinks.
 * Deterministic detection — the LLM is only used later to explain + patch.
 */
const INJECTION_PATTERNS = [
  {
    id: 'sql_string_concat',
    label: 'SQL query built by string concatenation',
    severity: 'high',
    confidence: 'medium',
    regex: /\b(?:select|insert into|update|delete from|drop table|alter table|create table)\b[\s\S]{0,120}?['"`]\s*\+/gi,
    description:
      'A SQL statement appears to be assembled by string concatenation (+). If any concatenated fragment comes from user input, this is a classic SQL injection vector.',
    fix: 'Use parameterized queries / prepared statements, e.g. `SELECT * FROM users WHERE email = ?` with the value passed as a bound parameter.',
  },
  {
    id: 'sql_template_literal',
    label: 'SQL query built with template literal',
    severity: 'high',
    confidence: 'medium',
    regex: /\b(?:select|insert into|update|delete from|drop table)\b[\s\S]{0,120}?\$\{/gi,
    description:
      'A SQL statement appears to interpolate values via a template literal (${…}). If the interpolated value is user-controlled, this is a SQL injection vector.',
    fix: 'Use parameterized queries. Never interpolate values directly into a SQL string.',
  },
  {
    id: 'eval',
    label: 'eval() usage',
    severity: 'high',
    confidence: 'high',
    regex: /\beval\s*\(/g,
    description:
      'eval() executes arbitrary strings as code. If anything user-controlled reaches it, this is a remote code execution (RCE) risk.',
    fix: 'Remove eval(). Parse data with JSON.parse() or a purpose-built parser instead of executing it.',
  },
  {
    id: 'new_function',
    label: 'new Function() usage',
    severity: 'medium',
    confidence: 'medium',
    regex: /\bnew\s+Function\s*\(/g,
    description:
      'new Function() compiles strings into functions at runtime — the same RCE class of risk as eval().',
    fix: 'Replace with safe, structured logic or a constrained expression evaluator.',
  },
  {
    id: 'child_process_exec',
    label: 'child_process exec/spawn with dynamic input',
    severity: 'high',
    confidence: 'medium',
    regex: /child_process\s*\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(/g,
    description:
      'A child process is spawned from Node. If the command string includes user input, this is a command injection vector.',
    fix: 'Never interpolate user input into shell commands. Use execFile/spawn with an argument array, and validate inputs against an allowlist.',
  },
  {
    id: 'os_system',
    label: 'os.system() (Python)',
    severity: 'high',
    confidence: 'medium',
    regex: /\bos\.system\s*\(/g,
    description:
      'os.system() runs a shell command. User input reaching this is a command injection vector.',
    fix: 'Replace with subprocess.run([...]) using an argument list (no shell=True), and validate inputs.',
  },
  {
    id: 'subprocess_shell',
    label: 'subprocess with shell=True (Python)',
    severity: 'high',
    confidence: 'high',
    regex: /subprocess\s*\.\s*(?:call|run|Popen|check_output|check_call)\s*\([^)]*\bshell\s*=\s*True/g,
    description:
      'Python subprocess invoked with shell=True — the command is run through a shell, making it injectable if any part is user-controlled.',
    fix: 'Drop shell=True and pass the command as an argument list.',
  },
  {
    id: 'pickle_loads',
    label: 'pickle.loads() (Python)',
    severity: 'high',
    confidence: 'medium',
    regex: /\bpickle\s*\.\s*loads?\s*\(/g,
    description:
      'Unpickling untrusted data can execute arbitrary code during deserialization (Python deserialization RCE).',
    fix: 'Never unpickle untrusted data. Use a safe serialization format like JSON.',
  },
  {
    id: 'yaml_load',
    label: 'Unsafe YAML load() (Python)',
    severity: 'medium',
    confidence: 'medium',
    regex: /\byaml\.(?:load|load_all)\s*\(/g,
    description:
      'PyYAML load() can instantiate arbitrary Python objects (yaml deserialization RCE) when no SafeLoader is used.',
    fix: 'Use yaml.safe_load() instead of yaml.load().',
  },
  {
    id: 'inner_html',
    label: 'innerHTML assignment (XSS)',
    severity: 'medium',
    confidence: 'low',
    regex: /\.innerHTML\s*=/g,
    description:
      'Assigning to innerHTML with dynamic content can lead to DOM-based XSS if the content is not sanitized.',
    fix: 'Use textContent, or sanitize HTML with a library like DOMPurify before assignment.',
  },
  {
    id: 'dangerously_set_inner_html',
    label: 'dangerouslySetInnerHTML (React XSS)',
    severity: 'medium',
    confidence: 'low',
    regex: /dangerouslySetInnerHTML\s*=/g,
    description:
      'React dangerouslySetInnerHTML bypasses React escaping. Dynamic HTML passed here is an XSS vector.',
    fix: 'Render via JSX, or sanitize with DOMPurify before passing to dangerouslySetInnerHTML.',
  },
  {
    id: 'document_write',
    label: 'document.write() (XSS)',
    severity: 'medium',
    confidence: 'low',
    regex: /\bdocument\.write\s*\(/g,
    description:
      'document.write() with dynamic content can inject arbitrary HTML/JS into the page.',
    fix: 'Use DOM APIs (createElement, textContent) instead of document.write().',
  },
];

export function scanForInjection(files) {
  const findings = [];
  for (const file of files) {
    let content;
    try {
      content = fs.readFileSync(file.full, 'utf8');
    } catch {
      continue;
    }
    for (const pattern of INJECTION_PATTERNS) {
      const matches = collectMatches(content, pattern.regex, file.rel);
      for (const m of matches) {
        findings.push({
          id: `injection-${findings.length + 1}`,
          type: 'injection',
          detectorId: pattern.id,
          label: pattern.label,
          severity: pattern.severity,
          confidence: pattern.confidence,
          file: file.rel,
          line: m.line,
          code: m.code,
          match: m.match,
          description: pattern.description,
          fix: pattern.fix,
        });
      }
    }
  }
  return findings;
}
