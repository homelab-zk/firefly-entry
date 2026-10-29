"""Firefly III receipt entry app.

Flow: unlock (PIN / passkey) -> pick type and own account(s) -> photo -> vision model reads
total, date, currency and shop -> user checks/edits -> transaction + photo posted to Firefly III.
The app never shows balances or past transactions.
"""
import asyncio
import base64
import difflib
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import time
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageOps
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

log = logging.getLogger("entry")
logging.basicConfig(level=logging.INFO)


def env(name, default=None):
    v = os.environ.get(name, default)
    if v is None:
        raise RuntimeError(f"missing env var {name}")
    return v


FIREFLY_URL = env("FIREFLY_URL").rstrip("/")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "").rstrip("/")  # optional with OCR_BACKEND=cloudflare (no fallback then)
OLLAMA_MODEL = env("OLLAMA_MODEL", "qwen2.5vl:3b")
OLLAMA_IMG_SIZE = int(env("OLLAMA_IMG_SIZE", "768"))
OLLAMA_NUM_GPU = int(env("OLLAMA_NUM_GPU", "0"))  # 0 = CPU; the GTX 1650 corrupts qwen2.5vl output
OLLAMA_TIMEOUT = int(env("OLLAMA_TIMEOUT", "600"))
# Who reads the receipt (scan and full text for the notes): "ollama" (local, slow) or "cloudflare"
# (Workers AI; photo leaves the network, Ollama is the fallback for both jobs).
OCR_BACKEND = env("OCR_BACKEND", "ollama")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_MODEL = env("CF_MODEL", "@cf/mistralai/mistral-small-3.1-24b-instruct")
CF_IMG_SIZE = int(env("CF_IMG_SIZE", "1280"))
CF_TIMEOUT = int(env("CF_TIMEOUT", "60"))
if OCR_BACKEND not in ("ollama", "cloudflare"):
    raise RuntimeError(f"bad OCR_BACKEND {OCR_BACKEND}")
if OCR_BACKEND == "ollama" and not OLLAMA_URL:
    raise RuntimeError("OCR_BACKEND=ollama needs OLLAMA_URL")
if OCR_BACKEND == "cloudflare" and not (CF_ACCOUNT_ID and CF_API_TOKEN):
    raise RuntimeError("OCR_BACKEND=cloudflare needs CF_ACCOUNT_ID and CF_API_TOKEN")
PIN_HASH = env("PIN_HASH")
RP_ID = env("RP_ID")
ORIGIN = env("ORIGIN")
TZ = ZoneInfo(env("TZ", "UTC"))
SESSION_IDLE = int(env("SESSION_IDLE_SECONDS", "180"))
DATA_DIR = Path(env("DATA_DIR", "/data"))
MAX_UPLOAD = 20 * 1024 * 1024
MAX_ATTACH = int(env("MAX_ATTACH_BYTES", "1000000"))  # photo attached to Firefly stays under ~1 MB

token_file = os.environ.get("FIREFLY_TOKEN_FILE")
FIREFLY_TOKEN = Path(token_file).read_text().strip() if token_file else env("FIREFLY_TOKEN")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
ollama_lock = asyncio.Semaphore(1)
sessions: dict[str, float] = {}
challenges: dict[str, bytes] = {}
jobs: dict[str, dict] = {}
fails = {"count": 0, "locked_until": 0.0}


# ---------- security headers ----------
@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' blob: data:; style-src 'self'; script-src 'self'; "
        "frame-ancestors 'none'"
    )
    return resp


# ---------- sessions ----------
def _secure(request: Request) -> bool:
    return request.url.scheme == "https"


def start_session(request: Request, response: Response):
    sid = secrets.token_urlsafe(32)
    sessions[sid] = time.time()
    response.set_cookie("sid", sid, httponly=True, secure=_secure(request), samesite="strict", path="/")


def require_session(request: Request) -> str:
    sid = request.cookies.get("sid")
    now = time.time()
    for k in [k for k, t in sessions.items() if now - t > SESSION_IDLE]:
        sessions.pop(k, None)
    if not sid or sid not in sessions:
        raise HTTPException(401, "locked")
    sessions[sid] = now
    return sid


# ---------- PIN ----------
PIN_FILE = DATA_DIR / "pin_hash"  # written by "Change PIN"; overrides PIN_HASH. Delete it to fall back to .env.


def hash_pin(pin: str, salt: bytes) -> str:
    return hashlib.scrypt(pin.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def check_pin(pin: str) -> bool:
    stored = PIN_FILE.read_text().strip() if PIN_FILE.exists() else PIN_HASH
    _, salt, want = stored.split(":")
    return hmac.compare_digest(hash_pin(pin, bytes.fromhex(salt)), want)


def pin_attempt(pin: str) -> bool:
    """check_pin() behind the shared lockout: 5 wrong PINs (login or change) lock for 5 minutes."""
    now = time.time()
    if now < fails["locked_until"]:
        raise HTTPException(429, f"Too many attempts. Try again in {int(fails['locked_until'] - now)}s.")
    if not check_pin(pin):
        fails["count"] += 1
        if fails["count"] >= 5:
            fails.update(count=0, locked_until=now + 300)
        return False
    fails["count"] = 0
    return True


class PinBody(BaseModel):
    pin: str


class PinChange(BaseModel):
    current: str
    new: str


@app.post("/api/login/pin")
async def login_pin(body: PinBody, request: Request, response: Response):
    if not pin_attempt(body.pin):
        raise HTTPException(401, "Wrong PIN")
    start_session(request, response)
    return {"ok": True}


@app.post("/api/pin")
async def change_pin(body: PinChange, sid: str = Depends(require_session)):
    if not pin_attempt(body.current):
        raise HTTPException(403, "Wrong current PIN")  # not 401: the client treats 401 as "session expired"
    if not (body.new.isdigit() and len(body.new) >= 4):
        raise HTTPException(400, "New PIN must be at least 4 digits")
    salt = os.urandom(16)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = PIN_FILE.with_suffix(".tmp")
    tmp.write_text(f"scrypt:{salt.hex()}:{hash_pin(body.new, salt)}")
    tmp.chmod(0o600)
    tmp.replace(PIN_FILE)
    log.info("PIN changed")
    return {"ok": True}


@app.post("/api/logout")
async def logout(request: Request, response: Response):
    sessions.pop(request.cookies.get("sid", ""), None)
    response.delete_cookie("sid", path="/")
    return {"ok": True}


@app.get("/api/session")
async def session_state(request: Request):
    sid = request.cookies.get("sid")
    ok = bool(sid and sid in sessions and time.time() - sessions[sid] <= SESSION_IDLE)
    return {"unlocked": ok, "passkey": bool(load_creds()), "idle": SESSION_IDLE}


# ---------- passkeys (fingerprint) ----------
def load_creds() -> list[dict]:
    f = DATA_DIR / "passkeys.json"
    return json.loads(f.read_text()) if f.exists() else []


def save_creds(creds: list[dict]):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    f = DATA_DIR / "passkeys.json"
    f.write_text(json.dumps(creds))
    f.chmod(0o600)


def json_response(s: str) -> Response:
    return Response(content=s, media_type="application/json")


@app.post("/api/passkey/register/options")
async def reg_options(sid: str = Depends(require_session)):
    opts = generate_registration_options(
        rp_id=RP_ID,
        rp_name="Firefly Entry",
        user_id=b"entry-user",
        user_name="entry",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"])) for c in load_creds()],
    )
    challenges["reg"] = opts.challenge
    return json_response(options_to_json(opts))


@app.post("/api/passkey/register/verify")
async def reg_verify(request: Request, sid: str = Depends(require_session)):
    cred = await request.json()
    try:
        v = verify_registration_response(
            credential=cred,
            expected_challenge=challenges.pop("reg"),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except Exception as e:
        log.warning("passkey registration failed: %s", e)
        raise HTTPException(400, "Passkey registration failed")
    creds = load_creds()
    creds.append(
        {
            "id": bytes_to_base64url(v.credential_id),
            "key": bytes_to_base64url(v.credential_public_key),
            "count": v.sign_count,
        }
    )
    save_creds(creds)
    return {"ok": True}


@app.post("/api/passkey/login/options")
async def login_options():
    creds = load_creds()
    if not creds:
        raise HTTPException(404, "No passkey registered")
    opts = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"])) for c in creds],
    )
    challenges["auth"] = opts.challenge
    return json_response(options_to_json(opts))


@app.post("/api/passkey/login/verify")
async def login_verify(request: Request, response: Response):
    cred = await request.json()
    creds = load_creds()
    match = next((c for c in creds if c["id"] == cred.get("id")), None)
    if not match or "auth" not in challenges:
        raise HTTPException(401, "Unknown passkey")
    try:
        v = verify_authentication_response(
            credential=cred,
            expected_challenge=challenges.pop("auth"),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(match["key"]),
            credential_current_sign_count=match["count"],
            require_user_verification=True,
        )
    except Exception as e:
        log.warning("passkey login failed: %s", e)
        raise HTTPException(401, "Passkey check failed")
    match["count"] = v.new_sign_count
    save_creds(creds)
    start_session(request, response)
    return {"ok": True}


# ---------- Firefly III ----------
def ff() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=f"{FIREFLY_URL}/api/v1",
        headers={"Authorization": f"Bearer {FIREFLY_TOKEN}", "Accept": "application/json"},
        timeout=60,
    )


async def list_accounts(c: httpx.AsyncClient, kind: str) -> list[dict]:
    out, page = [], 1
    while True:
        r = await c.get("/accounts", params={"type": kind, "limit": 100, "page": page})
        r.raise_for_status()
        j = r.json()
        for a in j["data"]:
            at = a["attributes"]
            if at.get("active", True):
                out.append({"id": a["id"], "name": at["name"], "currency": at.get("currency_code")})
        if page >= j["meta"]["pagination"]["total_pages"]:
            return out
        page += 1


@app.get("/api/meta")
async def meta(sid: str = Depends(require_session)):
    async with ff() as c:
        asset, expense, revenue = await asyncio.gather(
            list_accounts(c, "asset"), list_accounts(c, "expense"), list_accounts(c, "revenue")
        )
        r = await c.get("/currencies", params={"limit": 100})
        r.raise_for_status()
    currencies = [
        {"code": x["attributes"]["code"], "name": x["attributes"]["name"], "default": x["attributes"]["default"]}
        for x in r.json()["data"]
        if x["attributes"]["enabled"]
    ]
    return {
        "asset": asset,
        "expense": [a["name"] for a in expense],
        "revenue": [a["name"] for a in revenue],
        "currencies": currencies,
    }


# ---------- vision model ----------
def fit_under(im: Image.Image, limit: int) -> bytes:
    """JPEG of `im` no larger than `limit` bytes: lower quality first, then shrink."""
    side = 2000
    while True:
        img = im.copy()
        img.thumbnail((side, side))
        for q in (85, 75, 65, 55, 45):
            buf = io.BytesIO()
            img.save(buf, "JPEG", quality=q, optimize=True)
            if buf.tell() <= limit:
                return buf.getvalue()
        if side <= 600:
            return buf.getvalue()
        side = int(side * 0.8)


def thumb_jpeg(im: Image.Image, size: int) -> bytes:
    small = im.copy()
    small.thumbnail((size, size))
    o = io.BytesIO()
    small.save(o, "JPEG", quality=85)
    return o.getvalue()


def prep_images(raw: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (attachment_jpeg, ollama_jpeg, cloudflare_jpeg). Applies EXIF rotation."""
    im = ImageOps.exif_transpose(Image.open(io.BytesIO(raw))).convert("RGB")
    attach = fit_under(im, MAX_ATTACH)
    ocr = thumb_jpeg(im, OLLAMA_IMG_SIZE)
    cf = thumb_jpeg(im, CF_IMG_SIZE) if OCR_BACKEND == "cloudflare" else b""
    return attach, ocr, cf


async def ask_ollama(img: bytes, prompt: str, as_json: bool, **opts) -> str:
    if not OLLAMA_URL:
        raise RuntimeError("no Ollama configured (OLLAMA_URL)")
    body = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "keep_alive": "15m",
        "options": {"temperature": 0, "num_gpu": OLLAMA_NUM_GPU, **opts},
        "messages": [{"role": "user", "content": prompt, "images": [base64.b64encode(img).decode()]}],
    }
    if as_json:
        body["format"] = "json"
    async with ollama_lock:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as c:
            r = await c.post(f"{OLLAMA_URL}/api/chat", json=body)
            r.raise_for_status()
            return r.json()["message"]["content"]


async def ask_cloudflare(img: bytes, prompt: str, max_tokens: int = 300) -> str:
    """Workers AI via its OpenAI-compatible endpoint. Not behind ollama_lock: it doesn't load the local box."""
    body = {
        "model": CF_MODEL,
        "temperature": 0,
        "max_tokens": max_tokens,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + base64.b64encode(img).decode()}},
                ],
            }
        ],
    }
    async with httpx.AsyncClient(timeout=CF_TIMEOUT) as c:
        r = await c.post(
            f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/v1/chat/completions",
            json=body,
            headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
        )
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        return r.json()["choices"][0]["message"]["content"]


def extract_json(raw: str) -> dict:
    """Models without a JSON mode wrap the object in prose or ``` fences."""
    m = re.search(r"\{.*\}", raw, re.S)
    return json.loads(m.group(0) if m else raw)


def parse_amount(v) -> Decimal | None:
    if v is None:
        return None
    s = re.sub(r"[^\d.]", "", str(v).replace(",", ""))
    try:
        d = Decimal(s)
    except InvalidOperation:
        return None
    return d.quantize(Decimal("0.01")) if d > 0 else None


SCAN_PROMPT = (
    'Return JSON {"merchant": string, "total": number, "date_text": string or null, "date": string or null, '
    '"currency": string or null}. '
    "merchant = the shop or company name. total = the final total amount due/paid on this receipt. "
    # Copying the printed text first stops the model from taking the phone camera's timestamp overlay instead.
    "date_text = the purchase date exactly as printed on the receipt paper (not a camera timestamp in the photo "
    "corner), or null. date = that date as YYYY-MM-DD, or null. "
    "currency = the ISO 4217 code (e.g. SRD, USD, EUR) only if the receipt prints a currency code or the euro sign; "
    "null for a bare $ sign or when no currency is shown."
)


def parse_date(v) -> str:
    """YYYY-MM-DD from the model, or "" when missing, invalid, in the future or more than a year old."""
    m = re.search(r"\d{4}-\d{2}-\d{2}", str(v or ""))
    try:
        d = date.fromisoformat(m.group(0)) if m else None
    except ValueError:
        return ""
    today = datetime.now(TZ).date()
    return d.isoformat() if d and today - timedelta(days=366) <= d <= today else ""


LEGAL_WORDS = re.compile(r"\b(n\.?\s?v|b\.?\s?v|ltd|inc|llc|corp|co)\b\.?")


def norm_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", LEGAL_WORDS.sub(" ", s.lower()))


def match_account(name: str, names: list[str]) -> str:
    """The existing account that the shop name on the receipt most likely is ("SUSHI-YA N.V." -> "Sushi-Ya"),
    so Firefly doesn't get a near-duplicate account. Done here, so the account list never goes to the model."""
    n = norm_name(name)
    if len(n) < 3:
        return ""
    best, score = "", 0.0
    for cand in names:
        c = norm_name(cand)
        if not c:
            continue
        if c == n:
            return cand
        short, long_ = sorted((c, n), key=len)
        s = 0.85 if len(short) >= 4 and short in long_ and len(short) / len(long_) >= 0.4 else 0.0
        s = max(s, difflib.SequenceMatcher(None, n, c).ratio())
        if s > score:
            best, score = cand, s
    return best if score >= 0.8 else ""
TEXT_PROMPT = (
    "Transcribe all the text on this receipt, line by line. Plain text only. "
    "Leave out any camera timestamp overlaid on the photo."
)


async def read_receipt(ocr_img: bytes, cf_img: bytes) -> str:
    if OCR_BACKEND == "cloudflare":
        try:
            return await ask_cloudflare(cf_img, SCAN_PROMPT)
        except Exception as e:
            log.warning("cloudflare scan failed, falling back to ollama: %s", e)
    return await ask_ollama(ocr_img, SCAN_PROMPT, as_json=True)


async def run_scan(job_id: str, ocr_img: bytes, cf_img: bytes):
    job = jobs[job_id]
    try:
        raw = await read_receipt(ocr_img, cf_img)
        j = extract_json(raw)
        job["total"] = str(parse_amount(j.get("total")) or "")
        job["merchant"] = str(j.get("merchant") or "").strip()[:100]
        job["date"] = parse_date(j.get("date"))
        cur = str(j.get("currency") or "").strip().upper()
        job["currency"] = cur if re.fullmatch(r"[A-Z]{3}", cur) else ""
        if job["merchant"]:
            try:
                async with ff() as c:
                    expense, revenue = await asyncio.gather(list_accounts(c, "expense"), list_accounts(c, "revenue"))
                job["expense"] = match_account(job["merchant"], [a["name"] for a in expense])
                job["revenue"] = match_account(job["merchant"], [a["name"] for a in revenue])
            except Exception as e:
                log.warning("account match failed: %s", e)
        job["status"] = "done"
    except Exception as e:
        log.warning("scan failed: %s", e)
        job["status"] = "error"
        job["error"] = "Could not read the receipt. Enter the amount manually."


@app.post("/api/scan")
async def scan(photo: UploadFile = File(...), sid: str = Depends(require_session)):
    raw = await photo.read(MAX_UPLOAD + 1)
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "Photo too large")
    try:
        attach, ocr, cf = await asyncio.to_thread(prep_images, raw)
    except Exception:
        raise HTTPException(400, "Not a valid image")
    now = time.time()
    for k in [k for k, v in jobs.items() if now - v["created"] > 1800]:
        jobs.pop(k, None)
    job_id = secrets.token_urlsafe(12)
    jobs[job_id] = {"created": now, "status": "running", "attach": attach, "ocr": ocr, "cf": cf}
    asyncio.create_task(run_scan(job_id, ocr, cf))
    return {"job": job_id}


@app.get("/api/scan/{job_id}")
async def scan_status(job_id: str, sid: str = Depends(require_session)):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    return {k: job.get(k) for k in ("status", "total", "merchant", "date", "currency", "expense", "revenue", "error")}


# ---------- submit ----------
class Account(BaseModel):
    id: str | None = None
    name: str | None = None


class SubmitBody(BaseModel):
    job: str | None = None  # None = manual entry without a receipt photo
    type: str  # withdrawal | deposit | transfer
    debit: Account  # money leaves this account  -> Firefly source
    credit: Account  # money arrives here        -> Firefly destination
    currency: str
    amount: str
    foreign_currency: str | None = None  # e.g. receipt in USD paid from an SRD account
    foreign_amount: str | None = None
    description: str
    date: str | None = None  # YYYY-MM-DD; empty or today = now


def side(prefix: str, a: Account) -> dict:
    if a.id:
        return {f"{prefix}_id": a.id}
    if a.name and a.name.strip():
        return {f"{prefix}_name": a.name.strip()}
    raise HTTPException(400, f"Missing {prefix} account")


def firefly_error(r: httpx.Response) -> str:
    try:
        j = r.json()
        errs = j.get("errors")
        if errs:
            return "; ".join(m for v in errs.values() for m in v)
        return j.get("message") or r.text[:200]
    except Exception:
        return r.text[:200]


MD_BLOCK_START = re.compile(r"^[#>*+=_|-]")
MD_ORDERED = re.compile(r"^(\d+)([.)])(\s|$)")


def notes_markdown(lines: list[str]) -> str:
    """Firefly renders notes as Markdown: end lines with two spaces (hard break) so the receipt keeps
    its line breaks, and escape leading characters that would turn a line into a heading, list or rule.
    (A ``` code block renders as a white box in Firefly's dark theme.)"""
    out = []
    for ln in lines:
        ln = ln.strip().replace("`", "'")
        if MD_BLOCK_START.match(ln):
            ln = "\\" + ln
        ln = MD_ORDERED.sub(r"\1\\\2\3", ln)
        out.append(ln + "  " if ln else "")
    return "\n".join(out).strip()


async def read_text(ocr_img: bytes, cf_img: bytes) -> tuple[str, str]:
    """Full receipt text and the model that read it; Cloudflare first (seconds), Ollama as fallback (minutes)."""
    if OCR_BACKEND == "cloudflare":
        try:
            return await ask_cloudflare(cf_img, TEXT_PROMPT, max_tokens=3000), CF_MODEL.rsplit("/", 1)[-1]
        except Exception as e:
            log.warning("cloudflare transcription failed, falling back to ollama: %s", e)
    text = await ask_ollama(ocr_img, TEXT_PROMPT, as_json=False, num_predict=1200, repeat_penalty=1.15)
    return text, OLLAMA_MODEL


async def transcribe_into_notes(group_id: str, journal_id: str, ocr_img: bytes, cf_img: bytes):
    try:
        text, model = await read_text(ocr_img, cf_img)
        lines, prev = [], None
        for ln in text.splitlines():
            if ln.strip() and ln.strip() == prev:
                continue
            prev = ln.strip()
            lines.append(ln)
        notes = f"Auto-read from photo by {model}; may contain errors.\n\n" + notes_markdown(lines)
        async with ff() as c:
            r = await c.put(
                f"/transactions/{group_id}",
                json={"apply_rules": False, "transactions": [{"transaction_journal_id": journal_id, "notes": notes}]},
            )
            r.raise_for_status()
        log.info("notes added to transaction %s", group_id)
    except Exception as e:
        log.warning("transcription failed for %s: %s", group_id, e)


async def check_currency(body: "SubmitBody"):
    """Firefly silently re-labels the amount in the asset account's own currency, so refuse a mismatch.
    A transfer's destination may instead be in the foreign currency (Firefly books the foreign amount there)."""
    async with ff() as c:
        for a, is_credit in ((body.debit, False), (body.credit, True)):
            if not a.id:
                continue
            r = await c.get(f"/accounts/{a.id}")
            if r.status_code >= 400:
                raise HTTPException(422, "Account not found")
            at = r.json()["data"]["attributes"]
            want = body.foreign_currency if body.type == "transfer" and is_credit and body.foreign_currency else body.currency
            if at.get("currency_code") != want:
                raise HTTPException(
                    422, f"{at['name']} is in {at.get('currency_code')}, not {want}. Pick the matching currency."
                )


@app.post("/api/submit")
async def submit(body: SubmitBody, sid: str = Depends(require_session)):
    job = jobs.get(body.job) if body.job else None
    if body.job and not job:
        raise HTTPException(404, "Photo expired. Please start again.")
    if body.type not in ("withdrawal", "deposit", "transfer"):
        raise HTTPException(400, "Bad type")
    amount = parse_amount(body.amount)
    if not amount:
        raise HTTPException(400, "Enter a valid amount")
    desc = body.description.strip() or ("Receipt" if job else "Manual entry")
    foreign = {}
    if body.foreign_currency:
        if body.foreign_currency == body.currency:
            raise HTTPException(400, "Foreign currency must differ from the currency")
        famount = parse_amount(body.foreign_amount)
        if not famount:
            raise HTTPException(400, "Enter a valid foreign amount")
        foreign = {"foreign_amount": str(famount), "foreign_currency_code": body.foreign_currency}
    now = datetime.now(TZ)
    try:
        day = date.fromisoformat(body.date) if body.date else now.date()
    except ValueError:
        raise HTTPException(400, "Bad date")
    if day > now.date():
        raise HTTPException(400, "The date is in the future")
    await check_currency(body)
    # A late entry gets midday of its own day: the real time is unknown.
    when = (now if day == now.date() else datetime(day.year, day.month, day.day, 12, tzinfo=TZ)).isoformat(timespec="seconds")
    tx = {
        "type": body.type,
        "date": when,
        "amount": str(amount),
        "description": desc[:255],
        "currency_code": body.currency,
        **foreign,
        **side("source", body.debit),
        **side("destination", body.credit),
    }
    async with ff() as c:
        r = await c.post(
            "/transactions",
            json={"error_if_duplicate_hash": False, "apply_rules": False, "fire_webhooks": True, "transactions": [tx]},
        )
        if r.status_code >= 400:
            raise HTTPException(422, firefly_error(r))
        data = r.json()["data"]
        group_id = data["id"]
        journal_id = data["attributes"]["transactions"][0]["transaction_journal_id"]
        warn = None
        if not job:
            return {"ok": True, "id": group_id, "warning": None}  # manual entry: no photo to attach or transcribe
        try:
            stamp = datetime.now(TZ).strftime("%Y%m%d-%H%M%S")
            ar = await c.post(
                "/attachments",
                json={
                    "filename": f"receipt-{stamp}.jpg",
                    "attachable_type": "TransactionJournal",
                    "attachable_id": journal_id,
                    "title": f"Receipt {stamp}",
                },
            )
            ar.raise_for_status()
            aid = ar.json()["data"]["id"]
            ur = await c.post(
                f"/attachments/{aid}/upload", content=job["attach"], headers={"Content-Type": "application/octet-stream"}
            )
            ur.raise_for_status()
        except Exception as e:
            log.warning("attachment failed: %s", e)
            warn = "Transaction saved, but the photo could not be attached."
    asyncio.create_task(transcribe_into_notes(group_id, journal_id, job["ocr"], job["cf"]))
    jobs.pop(body.job, None)
    return {"ok": True, "id": group_id, "warning": warn}


# ---------- static ----------
@app.get("/")
async def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
