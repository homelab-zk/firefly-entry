# Firefly Entry

A small phone-first web app for adding transactions to [Firefly III](https://www.firefly-iii.org/) from a receipt photo.

Pick Debit / Credit / Transfer and your account, take a photo of the receipt, and a vision model fills in the **total, date, currency and shop**. You check or correct everything, and the app saves the transaction in Firefly with the photo attached. A few seconds later the full receipt text is added to the transaction's notes. No receipt? Use **Manual entry**.

The point is quick entry and privacy on the go: Firefly itself stays closed on the phone, and the app never shows balances or past transactions, only account names.

## Features

- Unlock with a PIN or the phone's fingerprint (passkey; each phone registers its own). Locks after 3 minutes idle; 5 wrong PINs lock it for 5 minutes. Change the PIN in the app.
- Receipt reading with **Cloudflare Workers AI** (Mistral Small 3.1, a few seconds, free daily allowance) or your own **Ollama** (local, slower); with Cloudflare, Ollama can be the fallback.
- Fills date, total, currency and shop. The shop is matched to your existing expense/revenue accounts (on the server; the account list is never sent to the model), so you don't get near-duplicate accounts.
- Foreign currency: a USD receipt paid from a EUR account gets Firefly's foreign amount; you type what the account was charged.
- Backdated entries (saved at 12:00 that day), manual entry without a photo, zoomable photo preview.
- Full receipt text written into the Firefly notes (Markdown, line breaks kept).
- Installable on the phone's home screen (PWA, no offline cache on purpose).

## Requirements

- Docker with Docker Compose.
- Firefly III (tested with 6.2) and a **Personal Access Token** from it.
- An **HTTPS** hostname through a reverse proxy (Nginx Proxy Manager, Caddy, Traefik, ...). Fingerprint unlock only works over HTTPS, and `RP_ID` / `ORIGIN` must match the hostname exactly.
- One receipt reader:
  - **Cloudflare** account with Workers AI (free tier is plenty: about 135 "neurons" per photo, 10,000 free per day), or
  - **Ollama** with a vision model, e.g. `qwen2.5vl:3b`.

**Security:** the app holds a token with full access to your Firefly. Keep it on your home network or behind a VPN (WireGuard, Tailscale, ...). Don't expose it to the open internet.

**Privacy:** with `OCR_BACKEND=cloudflare`, a copy of each receipt photo is sent to Cloudflare. Use `OCR_BACKEND=ollama` to keep everything local.

## Setup

```bash
git clone https://github.com/<owner>/firefly-entry.git
cd firefly-entry
cp docker-compose.example.yml docker-compose.yml
install -m 600 .env.example .env
mkdir -m 700 data
```

1. **Firefly token.** In Firefly: *Options → Profile → OAuth → Personal Access Tokens → Create new token*. Save it as one line:
   ```bash
   install -m 600 /dev/null firefly_token.txt
   nano firefly_token.txt        # paste the token, save
   ```
   Check it (prints `200`, not the token):
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $(cat firefly_token.txt)" \
     -H 'Accept: application/json' http://<firefly-host>:8080/api/v1/about/user
   ```
2. **PIN.** `python3 gen_pin_hash.py` asks for the PIN twice and prints the `PIN_HASH` value.
3. **Cloudflare** (if used). Dashboard → *My Profile → API Tokens → Create Token →* template **Workers AI**. Your account ID is on the dashboard's overview page. Put both in `.env`.
4. **Edit `.env`**: `FIREFLY_URL`, `RP_ID`, `ORIGIN`, `PIN_HASH`, the receipt reader settings, `TZ`. Every setting is explained in `.env.example`.
5. **Edit `docker-compose.yml`**: host port, token file name, and `user:` (your `id -u`:`id -g`, so the container can read the mode-600 token file).
6. **Start.**
   ```bash
   docker compose up -d --build
   docker logs firefly_entry        # expect "Application startup complete"
   ```
   A missing setting stops the container with `missing env var ...`.
7. **Reverse proxy.** Point your HTTPS hostname (`RP_ID`) to `http://<docker-host>:<port>`. Only the proxy should reach that port.
8. **Phone.** Open `https://<your-hostname>`, unlock with the PIN, tap **Add fingerprint for this phone**, then install it from the browser menu (*Add to Home screen*).

## Update

```bash
cd firefly-entry
git pull
docker compose up -d --build
```

Your `.env`, `docker-compose.yml`, token file and `data/` are not tracked by git and stay as they are. A restart logs everyone out and drops receipt notes that were still being written.

## Troubleshooting

| Problem | Fix |
|---|---|
| Fingerprint setup fails | `RP_ID` / `ORIGIN` must equal the HTTPS hostname exactly; plain HTTP doesn't work. Changing the hostname later means registering fingerprints again. |
| Forgot the PIN | Delete `data/pin_hash` (the PIN set in the app); the `PIN_HASH` from `.env` works again. Or set a new one with `gen_pin_hash.py`. |
| "Too many attempts" | Wait 5 minutes, or restart the container. |
| `... is in EUR, not USD` | The amount is always in the account's currency; use the receipt currency field for a foreign amount. |
| No notes in Firefly | Reload the transaction page (Firefly doesn't refresh by itself). Check `docker logs firefly_entry` for `notes added` or `transcription failed`. |
| Scans are slow | Cloudflare failed and Ollama took over: look for `falling back to ollama` in the logs (quota, token, outage). |
| `KeyError: 'ContainerConfig'` | Old `docker-compose` v1: run `docker-compose down` before `docker-compose up -d --build`. |
| Ollama returns `!!!!!!` | Some small GPUs corrupt `qwen2.5vl` output; set `OLLAMA_NUM_GPU=0` (CPU). |

## How it works

FastAPI backend (`app/main.py`) and a plain-JavaScript page (`app/static/`). The photo is posted to `/api/scan`; a background task asks the model for `{merchant, total, date, currency}` and the page polls for the result. `/api/submit` creates the Firefly transaction, uploads the photo as an attachment, and a second background task transcribes the receipt into the notes. Sessions, scans and challenges live in memory; only passkeys and the app PIN are stored in `data/`. The app is meant for one household: everyone shares one Firefly user and one app PIN.

## License

MIT, see [LICENSE](LICENSE).
