import fs from 'node:fs';
import { collectMatches } from '../util.js';

/**
 * Well-known secret patterns. These are real, deterministic detectors —
 * no LLM involved in detection, which is the whole point.
 */
const SECRET_PATTERNS = [
  {
    id: 'aws_access_key_id',
    label: 'AWS Access Key ID',
    severity: 'critical',
    confidence: 'high',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    envVar: 'AWS_ACCESS_KEY_ID',
    description:
      'A hardcoded AWS Access Key ID. Anyone who can read this repo can make authenticated AWS API calls billed to the account owner — including spinning up expensive infrastructure.',
    fix: 'Remove the key from source and load it from an environment variable or a secrets manager (AWS Secrets Manager, Vault, etc.).',
  },
  {
    id: 'aws_secret_key',
    label: 'AWS Secret Access Key',
    severity: 'critical',
    confidence: 'high',
    regex: /\b(?:aws_secret_access_key|aws_access_key_id)\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]/g,
    envVar: 'AWS_SECRET_ACCESS_KEY',
    description:
      'A hardcoded AWS Secret Access Key alongside its identifier. This pair is enough to fully authenticate to AWS.',
    fix: 'Remove from source. Load via environment variables or a secrets manager, and rotate the leaked key immediately.',
  },
  {
    id: 'github_token',
    label: 'GitHub Personal Access Token',
    severity: 'critical',
    confidence: 'high',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    envVar: 'GITHUB_TOKEN',
    description:
      'A GitHub Personal Access Token grants repository and account access scoped to its permissions. Leaked tokens are routinely scraped within minutes.',
    fix: 'Revoke the token in GitHub settings, then load it from an environment variable or secret store.',
  },
  {
    id: 'gitlab_token',
    label: 'GitLab Personal Access Token',
    severity: 'high',
    confidence: 'high',
    regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    envVar: 'GITLAB_TOKEN',
    description: 'A GitLab Personal Access Token exposed in source code.',
    fix: 'Revoke it and move it to environment variables.',
  },
  {
    id: 'openai_key',
    label: 'OpenAI API Key',
    severity: 'critical',
    confidence: 'high',
    regex: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/g,
    envVar: 'OPENAI_API_KEY',
    description:
      'An OpenAI project API key. Leaked keys are frequently abused for resale within hours, racking up charges.',
    fix: 'Revoke in the OpenAI dashboard and load from environment variables.',
  },
  {
    id: 'openai_key_legacy',
    label: 'OpenAI API Key (legacy format)',
    severity: 'critical',
    confidence: 'high',
    regex: /\bsk-[A-Za-z0-9]{20,}\b/g,
    envVar: 'OPENAI_API_KEY',
    description: 'An OpenAI API key in the legacy sk-… format.',
    fix: 'Revoke it and load from environment variables.',
  },
  {
    id: 'anthropic_key',
    label: 'Anthropic API Key',
    severity: 'critical',
    confidence: 'high',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    envVar: 'ANTHROPIC_API_KEY',
    description: 'An Anthropic API key exposed in source code.',
    fix: 'Revoke it and move it to environment variables.',
  },
  {
    id: 'slack_token',
    label: 'Slack Token',
    severity: 'high',
    confidence: 'high',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    envVar: 'SLACK_TOKEN',
    description: 'A Slack API token (bot, user, or app token) exposed in source.',
    fix: 'Revoke it from the Slack app settings and use environment variables.',
  },
  {
    id: 'stripe_key',
    label: 'Stripe API Key',
    severity: 'critical',
    confidence: 'high',
    regex: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g,
    envVar: 'STRIPE_SECRET_KEY',
    description:
      'A live Stripe secret/restricted key. This can read and mutate payment data — the most damaging kind of leak.',
    fix: 'Revoke it in the Stripe dashboard and load from environment variables.',
  },
  {
    id: 'google_api_key',
    label: 'Google API Key',
    severity: 'medium',
    confidence: 'high',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    envVar: 'GOOGLE_API_KEY',
    description: 'A Google API key exposed in source code.',
    fix: 'Restrict and rotate the key in Google Cloud Console, then load from environment variables.',
  },
  {
    id: 'npm_token',
    label: 'npm Access Token',
    severity: 'high',
    confidence: 'high',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    envVar: 'NPM_TOKEN',
    description: 'An npm registry access token exposed in source.',
    fix: 'Revoke it on npmjs.com and use environment variables.',
  },
  {
    id: 'twilio_key',
    label: 'Twilio API Key',
    severity: 'high',
    confidence: 'high',
    regex: /\bSK[0-9a-fA-F]{32}\b/g,
    envVar: 'TWILIO_API_KEY',
    description: 'A Twilio API key (SK… format) exposed in source.',
    fix: 'Revoke it and move it to environment variables.',
  },
  {
    id: 'private_key',
    label: 'Private Key Block',
    severity: 'critical',
    confidence: 'high',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    envVar: 'PRIVATE_KEY',
    description:
      'A private key (RSA/EC/OpenSSH/etc.) embedded in source. Anyone with this file can impersonate the key owner.',
    fix: 'Remove the key from the repo (it should never have been committed) and rotate it.',
  },
  {
    id: 'hardcoded_credential',
    label: 'Possible hardcoded credential',
    severity: 'medium',
    confidence: 'low',
    regex:
      /\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[=:]\s*['"][^'"\s]{8,}['"]/gi,
    envVar: 'SECRET_VALUE',
    description:
      'A value that looks like a credential (password/secret/token/api key) assigned in source code. May be a false positive — but worth verifying.',
    fix: 'Verify whether this is a real credential. If so, move it to environment variables; if it is a placeholder or test value, mark it clearly.',
  },
];

export function scanForSecrets(files) {
  const findings = [];
  for (const file of files) {
    let content;
    try {
      content = fs.readFileSync(file.full, 'utf8');
    } catch {
      continue;
    }
    for (const pattern of SECRET_PATTERNS) {
      const matches = collectMatches(content, pattern.regex, file.rel);
      for (const m of matches) {
        findings.push({
          id: `secret-${findings.length + 1}`,
          type: 'secret',
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
          envVar: pattern.envVar,
        });
      }
    }
  }
  return findings;
}
