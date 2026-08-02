// Deliberately vulnerable — used only as a PATCH demo/testing fixture.
// DO NOT use this code in production.

const express = require('express');
const app = express();

// === PLANTED SECRETS ===
// (all values are fake / documented examples — nothing real is leaked)
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'; // AWS docs example key
const openaiKey = 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF';
const slackToken = 'xoxb-1234567890-abcdefghij';
const stripeKey = 'sk_live_51H4abcdefghijklmnopqrstuvwxyz';

// === PLANTED SQL INJECTION ===
app.get('/user', (req, res) => {
  const email = req.query.email;
  // BAD: string concatenation into SQL
  const query = 'SELECT * FROM users WHERE email = "' + email + '"';
  db.query(query, (err, rows) => {
    res.json(rows);
  });
});

// === PLANTED eval ===
function applyFilter(expr, input) {
  // BAD: eval on potentially user-controlled input
  return eval(expr);
}

// === PLANTED command injection ===
const child_process = require('child_process');
app.post('/deploy', (req, res) => {
  const branch = req.body.branch;
  // BAD: user input interpolated into a shell command
  child_process.exec('git checkout ' + branch, (err, stdout) => {
    res.send(stdout);
  });
});

// === PLANTED XSS sink ===
app.get('/render', (req, res) => {
  const html = '<div>' + req.query.name + '</div>';
  // BAD: unsanitized HTML
  document.innerHTML = html;
});

app.listen(3000);
