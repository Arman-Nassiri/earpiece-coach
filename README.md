# Gibsel Cue

Real-time AI negotiation coach delivered via earpiece. Listens to the other party, transcribes speech, and whispers tactical response lines.

## Project Structure

```
gibsel-cue/
├── index.html      ← HTML skeleton (screens, DOM)
├── styles.css      ← All CSS (design system, screens, components)
├── app.js          ← All frontend JS (auth, coaching, Supabase, Stripe)
├── .gitignore
└── README.md
```

## Tech Stack

- **Frontend**: Vanilla HTML/CSS/JS — no build step, no framework
- **Auth**: Supabase (email/password, session persistence)
- **Payments**: Stripe Checkout
- **AI**: Multi-provider (OpenAI, Anthropic, Google, Azure, Meta) — BYOK or Pro server-side
- **Speech**: Web Speech API (Chrome/Safari)
- **TTS**: Web Speech Synthesis (earpiece output)

## Local Development

Just open `index.html` in Chrome. No build step required.

```bash
# Option 1: Python simple server (recommended — avoids CORS quirks)
python3 -m http.server 8080
# Then open http://localhost:8080

# Option 2: VS Code Live Server extension
# Right-click index.html → Open with Live Server
```

> **Note:** Stripe Checkout requires HTTPS. On localhost it will throw an error — this is expected. It works on the live domain (`cue.gibsel.com`).

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

## Environment / Config

All config is at the top of `app.js`:

| Variable | Description |
|---|---|
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_ANON` | Supabase anon public key |
| `STRIPE_KEY` | Stripe publishable key (safe to expose) |
| `STRIPE_PRICE` | Stripe Price ID for Pro subscription |
| `APP_URL` | Auto-detected from `window.location.origin` |

> The Supabase anon key and Stripe publishable key are safe to commit — they are designed to be public. Never commit secret keys.

## Roadmap

- [ ] VPS Express server (`/api/coach`, `/api/webhook`, `/api/billing-portal`)
- [ ] Stripe webhook → update `profiles.plan` in Supabase
- [ ] Post-session debrief (Pro feature)
- [ ] Practice mode — AI plays the other party (Premium)
- [ ] PWA manifest + service worker for offline prep
