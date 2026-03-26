# Gibsel Cue

Real-time AI negotiation coach delivered via earpiece. Listens to the other party, transcribes speech, and surfaces tactical response lines in real time.

## Project Structure

```
gibsel-cue/
├── index.html      ← HTML skeleton (screens, DOM)
├── styles.css      ← All CSS (design system, screens, components)
├── app.js          ← All frontend JS (BYOK flows, prep, chat, realtime live UI)
├── server.js       ← Minimal Node server for static hosting + OpenAI Realtime call setup
├── package.json
├── .gitignore
└── README.md
```

## Tech Stack

- **Frontend**: Vanilla HTML/CSS/JS — no build step, no framework
- **Server**: Minimal Node HTTP server for local/dev hosting and Realtime call negotiation
- **AI**: Multi-provider BYOK for prep/chat, OpenAI Realtime over WebRTC for live mode
- **Speech**: OpenAI Realtime transcription for live mode
- **TTS**: Optional browser speech synthesis for the earpiece toggle

## Local Development

Live mode now depends on the bundled Node server because the browser needs a same-origin endpoint that starts the OpenAI Realtime WebRTC call.

```bash
npm start
# Then open http://localhost:3000
```

Live mode auth options:

- Preferred: set `OPENAI_API_KEY` on the server
- Fallback: if the user entered an OpenAI BYOK key in the app, live mode can reuse that key through the local server

Optional environment variables:

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | Server-side OpenAI key for live mode |
| `OPENAI_REALTIME_MODEL` | Defaults to `gpt-realtime` |
| `OPENAI_TRANSCRIBE_MODEL` | Defaults to `gpt-4o-mini-transcribe` |

## VPS Deployment

Served as static files via nginx from `/var/www/gibsel-cue`.

```bash
# On the VPS
git clone https://github.com/Arman-Nassiri/earpiece-coach /var/www/gibsel-cue
```

nginx config:
```nginx
server {
    listen 80;
    server_name cue.gibsel.com;
    root /var/www/gibsel-cue;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Future: proxy API calls to Express
    # location /api/ {
    #     proxy_pass http://localhost:3001;
    # }
}
```

## Deploy Updates

```bash
# Local
git add . && git commit -m "your message"
git push origin main

# On VPS
cd /var/www/gibsel-cue && git pull
```

## Rollback

The pre-Realtime version is preserved as the git branch `backup/pre-realtime-live`.

## Roadmap

- [ ] VPS Express server (`/api/coach`, `/api/webhook`, `/api/billing-portal`)
- [ ] Stripe webhook → update `profiles.plan` in Supabase
- [ ] Post-session debrief (Pro feature)
- [ ] Practice mode — AI plays the other party (Premium)
- [ ] PWA manifest + service worker for offline prep
