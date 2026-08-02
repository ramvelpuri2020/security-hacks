// Render Workflow job runner — one-shot scan of a repo URL.
//
//   node scripts/workflow-run.js <repo-url>
//
// Runs the exact same pipeline as the live SSE scan (/api/scan), logs each
// step to stdout (visible in the Render Workflow run logs), and prints the
// final report between REPORT_START / REPORT_END markers so the workflow task
// (workflow/index.js) can parse it back into a JSON result.
import dotenv from 'dotenv';
import { runPipeline } from '../src/pipeline.js';

dotenv.config();

const url = process.argv[2];
if (!url) {
  console.error('Usage: node scripts/workflow-run.js <repo-url>');
  process.exit(1);
}

const emit = (type, data) => {
  const line = `[${type}] ${JSON.stringify(data).slice(0, 400)}`;
  if (type === 'error') console.error(line);
  else console.log(line);
};

try {
  const results = await runPipeline({ url, emit });
  console.log('REPORT_START');
  console.log(JSON.stringify(results));
  console.log('REPORT_END');
  process.exit(0);
} catch (err) {
  console.error(`FATAL: ${err.message}`);
  process.exit(1);
}
