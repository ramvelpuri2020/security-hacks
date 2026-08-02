# Security Scanner — Frontend

Next.js frontend for the PATCH security scanner. Paste a GitHub repo URL and
watch a live pipeline clone it, scan for secrets & injection risks, research
real CVEs (Tavily), and generate AI patches (Qwen) — all rendered in the browser.

## Getting Started

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Configuration

Create `frontend/.env.local` with the URL of your deployed backend:

```
NEXT_PUBLIC_API_BASE=https://your-backend.onrender.com
```

Without it, the frontend defaults to `http://localhost:4000` for local development.

## Scripts

- `npm run dev` — development server
- `npm run build` — production build
- `npm run lint` — lint
