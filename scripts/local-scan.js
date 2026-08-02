// Dev tool: run the full pipeline against a local directory without cloning.
//   node scripts/local-scan.js ./test-fixtures/vulnerable-app
import dotenv from 'dotenv';
import { runPipeline } from '../src/pipeline.js';

dotenv.config();

const target = process.argv[2];
if (!target) {
  console.error('Usage: node scripts/local-scan.js <path-to-repo>');
  process.exit(1);
}

const emit = (type, data) => {
  switch (type) {
    case 'step':
      console.log(`\n[${data.step.toUpperCase()}] ${data.message}`);
      break;
    case 'scan':
      console.log(`  files: ${data.filesScanned} | secrets: ${data.secrets} | injection: ${data.injection} | deps: ${data.dependencies}`);
      break;
    case 'finding':
      console.log(`  [${data.severity.toUpperCase()}] ${data.file}:${data.line} — ${data.label}${data.confidence !== 'high' ? ` (confidence: ${data.confidence})` : ''}`);
      break;
    case 'cve':
      if (data.dep) {
        const cves = data.cves && data.cves.length ? data.cves.join(', ') : 'no CVEs found';
        console.log(`  📦 ${data.dep.name}@${data.dep.version}: ${data.status}${data.status === 'ok' ? ` — ${cves}` : ''}${data.error ? ` (${data.error})` : ''}`);
      } else {
        console.log(`  📦 ${data.message || data.status}`);
      }
      break;
    case 'patch':
      console.log(`  ✏️  ${data.findingId}: ${data.llmError ? `[deterministic: ${data.llmError}]` : 'patch generated'}`);
      break;
    case 'error':
      console.error(`  ❌ ${data.message}`);
      break;
    case 'done':
      break;
    default:
      break;
  }
};

try {
  const results = await runPipeline({ localPath: target, emit });
  const { summary, meta } = results;
  console.log('\n' + '='.repeat(60));
  console.log('FINAL REPORT');
  console.log('='.repeat(60));
  console.log(`Repo:          ${meta.repo}`);
  console.log(`Files scanned: ${meta.filesScanned} (${(meta.scannedBytes / 1024).toFixed(1)} KB)`);
  console.log(`Findings:      ${summary.totalFindings} — ${JSON.stringify(summary.bySeverity)}`);
  console.log(`Dependencies:  ${summary.dependencies}`);
  console.log(`CVE lookup:    ${meta.cveLookup} | Patches: ${meta.llmMode}`);
  for (const f of results.findings) {
    console.log(`\n[${f.severity.toUpperCase()}] ${f.label}`);
    console.log(`  ${f.file}:${f.line}  ${f.code.slice(0, 120)}`);
    if (f.explanation) console.log(`  → ${f.explanation.slice(0, 180)}`);
    if (f.patch) {
      console.log('  Patch:');
      f.patch.split('\n').slice(0, 6).forEach((l) => console.log(`    ${l}`));
    }
  }
  if (results.cves.length && results.cves[0].status === 'skipped') {
    console.log('\n💡 Tip: set TAVILY_API_KEY in .env to enable live CVE lookup for dependencies.');
  }
  if (meta.llmMode === 'deterministic') {
    console.log('💡 Tip: set LLM_API_KEY (Qwen via DashScope, or OpenRouter) to generate AI patches.');
  }
  process.exit(0);
} catch (err) {
  console.error('\nFATAL:', err.message);
  process.exit(1);
}
