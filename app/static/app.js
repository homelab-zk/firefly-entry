"use strict";
const $ = (id) => document.getElementById(id);
const screens = ["lock", "form", "pinchange", "photo", "confirm", "done"];

const TYPES = {
  // debit = money leaves (Firefly source), credit = money arrives (Firefly destination)
  withdrawal: { debit: "asset", credit: "expense", dHint: "your account, money leaves", cHint: "who you paid" },
  deposit: { debit: "revenue", credit: "asset", dHint: "where the money came from", cHint: "your account, money arrives" },
  transfer: { debit: "asset", credit: "asset", dHint: "from your account", cHint: "to your account" },
};

const st = { meta: null, type: "withdrawal", idle: 180, job: null, poll: null, url: null, scanSeq: 0, hiddenAt: 0, idleTimer: null,
  fingerBusy: false, hiddenByFinger: false };

function show(name) {
  screens.forEach((s) => $(s).classList.toggle("hidden", s !== name));
  window.scrollTo(0, 0);
}

async function api(path, opts = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opts });
  if (r.status === 401 && path !== "/api/login/pin" && !path.startsWith("/api/passkey/login")) {
    await lock(false);
    throw new Error("Locked");
  }
  let data = null;
  try { data = await r.json(); } catch (_) { /* no body */ }
  if (!r.ok) throw new Error((data && (data.detail || data.message)) || `Error ${r.status}`);
  return data;
}
const post = (path, body) =>
  api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) });

// ---------- lock / idle ----------
function resetState() {
  closeViewer();
  clearInterval(st.poll);
  st.poll = null;
  st.scanSeq++;
  st.job = null;
  st.meta = null;
  if (st.url) URL.revokeObjectURL(st.url);
  st.url = null;
  $("thumb").removeAttribute("src");
  ["amount", "foreign-amount", "desc", "pin", "party"].forEach((i) => ($(i).value = ""));
  clearPinChange();
  ["file-cam", "file-up"].forEach((i) => ($(i).value = ""));
  ["form-msg", "photo-msg", "confirm-msg", "lock-msg"].forEach((i) => ($(i).textContent = ""));
}

async function lock(callServer = true, autoFinger = false) {
  if (callServer) { try { await fetch("/api/logout", { method: "POST", credentials: "same-origin" }); } catch (_) { /* offline */ } }
  resetState();
  await showLock(autoFinger);
}

function bumpIdle() {
  clearTimeout(st.idleTimer);
  if (!$("lock").classList.contains("hidden")) return;
  st.idleTimer = setTimeout(() => lock(true), st.idle * 1000);
}
["touchstart", "click", "keydown", "input"].forEach((e) => document.addEventListener(e, bumpIdle, { passive: true }));
document.addEventListener("visibilitychange", () => {
  // The fingerprint sheet itself may hide the page; don't re-prompt when it closes.
  if (document.hidden) { st.hiddenAt = Date.now(); st.hiddenByFinger = st.fingerBusy; return; }
  // Camera/gallery pickers also hide the page briefly; only lock after a real absence.
  if ($("lock").classList.contains("hidden")) {
    if (st.hiddenAt && Date.now() - st.hiddenAt > 90000) lock(true, true);
  } else if (!st.hiddenByFinger && fingerHere() && !$("btn-finger").classList.contains("hidden")) {
    fingerUnlock();
  }
});

async function showLock(autoFinger = false) {
  clearTimeout(st.idleTimer);
  show("lock");
  let s = { passkey: false };
  try { s = await (await fetch("/api/session", { credentials: "same-origin" })).json(); } catch (_) { /* ignore */ }
  const finger = s.passkey && window.PublicKeyCredential;
  $("btn-finger").classList.toggle("hidden", !finger);
  if (finger && autoFinger && fingerHere() && !document.hidden) fingerUnlock();
}

$("pin-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("lock-msg").textContent = "";
  try {
    await post("/api/login/pin", { pin: $("pin").value });
    $("pin").value = "";
    await enter();
  } catch (err) {
    $("pin").value = "";
    $("lock-msg").textContent = err.message;
  }
});

// ---------- passkeys ----------
const b64uToBuf = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
};
const bufToB64u = (buf) => {
  const b = String.fromCharCode(...new Uint8Array(buf));
  return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// Several phones can each register a passkey; this flag remembers whether *this* phone has one,
// so only it gets the automatic prompt and the others keep the "add fingerprint" link.
function fingerHere() {
  try { return localStorage.getItem("fingerHere") === "1"; } catch (_) { return false; }
}
function setFingerHere() {
  try { localStorage.setItem("fingerHere", "1"); } catch (_) { /* storage blocked */ }
}

async function fingerUnlock() {
  if (st.fingerBusy) return;
  st.fingerBusy = true;
  $("lock-msg").textContent = "";
  try {
    const o = await post("/api/passkey/login/options");
    o.challenge = b64uToBuf(o.challenge);
    (o.allowCredentials || []).forEach((c) => (c.id = b64uToBuf(c.id)));
    const c = await navigator.credentials.get({ publicKey: o });
    await post("/api/passkey/login/verify", {
      id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
      response: {
        authenticatorData: bufToB64u(c.response.authenticatorData),
        clientDataJSON: bufToB64u(c.response.clientDataJSON),
        signature: bufToB64u(c.response.signature),
        userHandle: c.response.userHandle ? bufToB64u(c.response.userHandle) : null,
      },
      clientExtensionResults: {},
    });
    setFingerHere();
    await enter();
  } catch (err) {
    if (err.name === "NotAllowedError") {
      $("lock-msg").textContent = "Fingerprint cancelled. Enter your PIN.";
      $("pin").focus();
    } else {
      $("lock-msg").textContent = err.message;
    }
  } finally {
    st.fingerBusy = false;
  }
}
$("btn-finger").addEventListener("click", fingerUnlock);

$("btn-setup-finger").addEventListener("click", async () => {
  $("form-msg").textContent = "";
  try {
    const o = await post("/api/passkey/register/options");
    o.challenge = b64uToBuf(o.challenge);
    o.user.id = b64uToBuf(o.user.id);
    (o.excludeCredentials || []).forEach((c) => (c.id = b64uToBuf(c.id)));
    const c = await navigator.credentials.create({ publicKey: o });
    await post("/api/passkey/register/verify", {
      id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
      response: {
        attestationObject: bufToB64u(c.response.attestationObject),
        clientDataJSON: bufToB64u(c.response.clientDataJSON),
        transports: c.response.getTransports ? c.response.getTransports() : [],
      },
      clientExtensionResults: {},
    });
    setFingerHere();
    $("btn-setup-finger").classList.add("hidden");
    $("form-msg").textContent = "";
    alert("Fingerprint unlock is set up on this phone.");
  } catch (err) {
    if (err.name === "InvalidStateError") {
      // excludeCredentials matched: this phone is already registered
      setFingerHere();
      $("btn-setup-finger").classList.add("hidden");
      $("form-msg").textContent = "This phone already has fingerprint unlock.";
    } else {
      $("form-msg").textContent = err.name === "NotAllowedError" ? "Fingerprint setup cancelled" : err.message;
    }
  }
});

// ---------- form ----------
async function enter() {
  const s = await (await fetch("/api/session", { credentials: "same-origin" })).json();
  st.idle = s.idle;
  st.meta = await api("/api/meta");
  $("btn-setup-finger").classList.toggle("hidden", (s.passkey && fingerHere()) || !window.PublicKeyCredential);
  setType("withdrawal");
  show("form");
  bumpIdle();
}

function fillSide(side, kind, hintText) {
  // Only your own (asset) accounts are picked here; the shop or payer comes from the receipt.
  $(`${side}-box`).classList.toggle("hidden", kind !== "asset");
  $(`${side}-hint`).textContent = hintText;
  if (kind === "asset") $(`${side}-select`).replaceChildren(new Option("Choose account...", ""), ...st.meta.asset.map((a) => new Option(`${a.name} (${a.currency})`, a.id)));
}

function setType(t) {
  st.type = t;
  document.querySelectorAll(".seg button").forEach((b) => b.classList.toggle("on", b.dataset.type === t));
  const c = TYPES[t];
  fillSide("debit", c.debit, c.dHint);
  fillSide("credit", c.credit, c.cHint);
  $("form-msg").textContent = "";
}
document.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => setType(b.dataset.type)));

function own(side) {
  const acc = st.meta.asset.find((x) => x.id === $(`${side}-select`).value);
  return acc ? { id: acc.id, label: acc.name, currency: acc.currency } : null;
}

// Checks the first screen and stores the chosen accounts; false when something is missing.
function takeAccounts() {
  const c = TYPES[st.type];
  const debit = c.debit === "asset" ? own("debit") : null, credit = c.credit === "asset" ? own("credit") : null;
  if ((c.debit === "asset" && !debit) || (c.credit === "asset" && !credit)) {
    $("form-msg").textContent = st.type === "transfer" ? "Choose both accounts." : "Choose your account.";
    return false;
  }
  if (debit && credit && debit.id === credit.id) { $("form-msg").textContent = "Accounts must be different."; return false; }
  $("form-msg").textContent = "";
  // `account` holds the transaction's currency; a transfer's destination may differ (foreign amount).
  st.sel = { debit, credit, account: debit || credit };
  return true;
}
$("btn-next").addEventListener("click", () => {
  if (!takeAccounts()) return;
  st.manual = false;
  $("photo-summary").textContent = summary();
  show("photo");
});
$("btn-manual").addEventListener("click", () => {
  if (!takeAccounts()) return;
  st.manual = true;
  resetKeepForm();
  if (st.url) URL.revokeObjectURL(st.url);
  st.url = null;
  $("thumb").removeAttribute("src");
  prepConfirm();
  $("party").focus();
});
$("btn-lock").addEventListener("click", () => lock(true));

// ---------- change PIN ----------
function clearPinChange() {
  ["pin-cur", "pin-new", "pin-new2"].forEach((i) => ($(i).value = ""));
  $("pinchange-msg").textContent = "";
}
$("btn-change-pin").addEventListener("click", () => { clearPinChange(); show("pinchange"); });
$("btn-pinchange-back").addEventListener("click", () => { clearPinChange(); show("form"); });
$("pinchange-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const cur = $("pin-cur").value, pin = $("pin-new").value;
  let msg = "";
  if (!/^\d{4,}$/.test(pin)) msg = "New PIN must be at least 4 digits.";
  else if (pin !== $("pin-new2").value) msg = "New PINs don't match.";
  else if (pin === cur) msg = "New PIN is the same as the current one.";
  if (msg) { $("pinchange-msg").textContent = msg; return; }
  $("pinchange-msg").textContent = "Saving...";
  try {
    await post("/api/pin", { current: cur, new: pin });
    clearPinChange();
    show("form");
    alert("PIN changed.");
  } catch (err) {
    clearPinChange();
    $("pinchange-msg").textContent = err.message;
  }
});
$("btn-photo-back").addEventListener("click", () => show("form"));

const summary = () => {
  const s = st.sel, acc = (a) => `${a.label} (${a.currency})`;
  if (st.type === "transfer") return `Transfer: ${acc(s.debit)} → ${acc(s.credit)}`;
  return st.type === "withdrawal" ? `Debit from ${acc(s.debit)}` : `Credit to ${acc(s.credit)}`;
};
const partyKind = () => ({ withdrawal: "expense", deposit: "revenue" })[st.type] || null;
const today = () => {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};
function hint(id, text, warn = false) {
  $(id).textContent = text;
  $(id).classList.toggle("warn", warn);
}

// Currency of the amount (the account's) and the foreign currency, if any.
function curs() {
  const cur = st.sel.account.currency;
  const other = st.type === "transfer" ? st.sel.credit.currency : $("rcur").value;
  return { cur, fcur: other && other !== cur ? other : "" };
}
function showAmounts() {
  const { cur, fcur } = curs();
  $("cur-label").textContent = cur;
  $("fcur-label").textContent = fcur;
  $("foreign-box").classList.toggle("hidden", !fcur);
  if (st.type === "transfer") {
    $("foreign-label").textContent = `Amount arriving in ${st.sel.credit.label}`;
    $("amount-label").textContent = fcur ? `Amount leaving ${st.sel.debit.label}` : "Amount";
  } else {
    $("foreign-label").textContent = "Total on receipt";
    $("amount-label").textContent = fcur ? `Amount charged to ${st.sel.account.label}` : "Total";
  }
  updateSave();
}
$("rcur").addEventListener("change", () => {
  // Keep the receipt total in whichever field now holds the receipt's amount.
  const { fcur } = curs(), a = $("amount"), f = $("foreign-amount");
  if (fcur && !f.value && a.value) { f.value = a.value; a.value = ""; }
  if (!fcur && !a.value && f.value) { a.value = f.value; f.value = ""; }
  hint("rcur-hint", fcur ? `not ${st.sel.account.currency}: type what the account was charged` : "");
  showAmounts();
});

function partyHint(note = "") {
  const v = $("party").value.trim(), kind = partyKind();
  if (!kind || !v) { hint("party-hint", ""); return; }
  const known = st.meta[kind].some((n) => n.toLowerCase() === v.toLowerCase());
  hint("party-hint", (known ? "Existing account" : "New account: Firefly will create it") + note, !known);
}
$("party").addEventListener("input", () => { partyHint(); updateSave(); });
$("date").addEventListener("input", () => { st.dateTouched = true; hint("date-hint", ""); updateSave(); });

// ---------- photo viewer ----------
// Full-screen view of the receipt; a history entry lets the phone's Back button close it.
function openViewer() {
  if (!st.url) return;
  $("viewer-img").src = st.url;
  $("viewer-scroll").classList.remove("zoom");
  $("viewer").classList.remove("hidden");
  history.pushState({ viewer: true }, "");
}
function closeViewer(fromBack = false) {
  if ($("viewer").classList.contains("hidden")) return;
  $("viewer").classList.add("hidden");
  $("viewer-img").removeAttribute("src");
  if (!fromBack && history.state && history.state.viewer) history.back();
}
$("thumb").addEventListener("click", openViewer);
$("viewer-close").addEventListener("click", () => closeViewer());
window.addEventListener("popstate", () => closeViewer(true));
$("viewer-img").addEventListener("click", (e) => {
  // Zoom to 2.5x around the tapped spot, or back to fit.
  const sc = $("viewer-scroll"), img = e.currentTarget, r = img.getBoundingClientRect();
  const fx = (e.clientX - r.left) / r.width, fy = (e.clientY - r.top) / r.height;
  if (sc.classList.toggle("zoom")) {
    sc.scrollLeft = fx * img.offsetWidth - sc.clientWidth / 2;
    sc.scrollTop = fy * img.offsetHeight - sc.clientHeight / 2;
  }
});

// ---------- photo + scan ----------
async function shrink(file) {
  try {
    const bmp = await createImageBitmap(file, { imageOrientation: "from-image" });
    const k = Math.min(1, 2000 / Math.max(bmp.width, bmp.height));
    const cv = document.createElement("canvas");
    cv.width = Math.round(bmp.width * k);
    cv.height = Math.round(bmp.height * k);
    cv.getContext("2d").drawImage(bmp, 0, 0, cv.width, cv.height);
    const blob = await new Promise((res) => cv.toBlob(res, "image/jpeg", 0.85));
    return blob || file;
  } catch (_) {
    return file;
  }
}

// Empty confirm screen for the chosen accounts; with st.manual there's no photo and nothing to wait for.
function prepConfirm() {
  $("confirm-title").textContent = st.manual ? "Manual entry" : "Confirm";
  $("confirm-summary").textContent = summary();
  ["thumb", "thumb-hint"].forEach((i) => $(i).classList.toggle("hidden", st.manual));
  const kind = partyKind(), cur = st.sel.account.currency;
  $("party-box").classList.toggle("hidden", !kind);
  $("rcur-box").classList.toggle("hidden", !kind);
  if (kind) {
    $("party-label").textContent = kind === "expense" ? "Paid to" : "Received from";
    $("party-list").replaceChildren(...st.meta[kind].map((n) => Object.assign(document.createElement("option"), { value: n })));
    const codes = st.meta.currencies.map((c) => c.code);
    $("rcur").replaceChildren(...(codes.includes(cur) ? [] : [cur]).concat(codes).map((c) => new Option(c, c)));
    $("rcur").value = cur;
  }
  $("party").value = "";
  hint("party-hint", "");
  hint("rcur-hint", "");
  st.dateTouched = false;
  $("date").value = today();
  $("date").max = today();
  hint("date-hint", "");
  $("foreign-amount").value = "";
  $("amount").value = "";
  $("desc").value = "";
  $("confirm-msg").textContent = "";
  $("reading").classList.add("hidden");
  $("btn-save").disabled = true;
  showAmounts();
  show("confirm");
}

async function onPhoto(e) {
  const f = e.target.files[0];
  if (!f) return;
  $("photo-msg").textContent = "";
  const seq = ++st.scanSeq;
  if (st.url) URL.revokeObjectURL(st.url);
  st.url = URL.createObjectURL(f);
  $("thumb").src = st.url;
  prepConfirm();
  $("reading").classList.remove("hidden");
  try {
    const fd = new FormData();
    fd.append("photo", await shrink(f), "receipt.jpg");
    const { job } = await api("/api/scan", { method: "POST", body: fd });
    if (seq !== st.scanSeq) return;
    st.job = job;
    updateSave();
    clearInterval(st.poll);
    st.poll = setInterval(() => pollScan(seq), 2500);
  } catch (err) {
    if (seq !== st.scanSeq) return;
    $("reading").classList.add("hidden");
    $("confirm-msg").textContent = "Upload failed: " + err.message;
  }
}
$("file-cam").addEventListener("change", onPhoto);
$("file-up").addEventListener("change", onPhoto);

async function pollScan(seq) {
  if (seq !== st.scanSeq || !st.job) return;
  try {
    const j = await api(`/api/scan/${st.job}`);
    if (seq !== st.scanSeq || j.status === "running") return;
    clearInterval(st.poll);
    $("reading").classList.add("hidden");
    if (j.status === "done") {
      const kind = partyKind(), { cur } = curs();
      if (kind && j.currency) {
        if ([...$("rcur").options].some((o) => o.value === j.currency)) {
          $("rcur").value = j.currency;
          hint("rcur-hint", j.currency === cur ? "from receipt" : `from receipt, not ${cur}: type what the account was charged`, j.currency !== cur);
        } else {
          hint("rcur-hint", `receipt says ${j.currency}, which isn't enabled in Firefly`, true);
        }
      } else if (kind) {
        hint("rcur-hint", `not on the receipt; using the account's ${cur}`, true);
      }
      showAmounts();
      // The scanned total belongs to the side whose currency the receipt is in.
      const { fcur } = curs();
      const target = $(fcur && (st.type !== "transfer" || j.currency === fcur) ? "foreign-amount" : "amount");
      if (!target.value && j.total) target.value = j.total;
      if (!j.total) $("confirm-msg").textContent = "Couldn't find a total. Enter it manually.";
      if (!st.dateTouched) {
        if (j.date) {
          $("date").value = j.date;
          hint("date-hint", j.date === today() ? "from receipt" : "from receipt, not today", j.date !== today());
        } else {
          hint("date-hint", "not found on the receipt; today", true);
        }
      }
      if (kind && !$("party").value) {
        const m = j[kind];
        $("party").value = m || j.merchant || "";
        partyHint(m && j.merchant && m !== j.merchant ? ` (receipt says "${j.merchant}")` : "");
      }
      if (!$("desc").value && j.merchant) $("desc").value = j.merchant;
    } else {
      $("confirm-msg").textContent = j.error || "Could not read the receipt.";
    }
    updateSave();
  } catch (_) { /* transient; keep polling */ }
}

const validAmount = (id) => /^\d+([.,]\d{1,2})?$/.test($(id).value.trim()) && parseFloat($(id).value.replace(",", ".")) > 0;
function updateSave() {
  const d = $("date").value, { fcur } = curs();
  $("btn-save").disabled = !((st.job || st.manual) && validAmount("amount") && (!fcur || validAmount("foreign-amount")) &&
    d && d <= today() && (!partyKind() || $("party").value.trim()));
}
["amount", "foreign-amount"].forEach((id) => $(id).addEventListener("input", updateSave));
$("btn-confirm-back").addEventListener("click", () => { resetKeepForm(); show(st.manual ? "form" : "photo"); });
function resetKeepForm() {
  clearInterval(st.poll);
  st.scanSeq++;
  st.job = null;
  ["file-cam", "file-up"].forEach((i) => ($(i).value = ""));
}

$("btn-save").addEventListener("click", async () => {
  $("btn-save").disabled = true;
  $("confirm-msg").textContent = "Saving...";
  const { cur, fcur } = curs();
  // Use the existing account's exact spelling so Firefly doesn't create a near-duplicate.
  const typed = $("party").value.trim(), kind = partyKind();
  const party = (kind && st.meta[kind].find((n) => n.toLowerCase() === typed.toLowerCase())) || typed;
  try {
    const r = await post("/api/submit", {
      job: st.manual ? null : st.job,
      type: st.type,
      debit: st.sel.debit ? { id: st.sel.debit.id } : { name: party },
      credit: st.sel.credit ? { id: st.sel.credit.id } : { name: party },
      currency: cur,
      amount: $("amount").value.trim().replace(",", "."),
      foreign_currency: fcur || null,
      foreign_amount: fcur ? $("foreign-amount").value.trim().replace(",", ".") : null,
      description: $("desc").value.trim() || party,
      date: $("date").value,
    });
    $("done-msg").textContent = r.warning || (st.manual ? "Transaction added." :
      "Transaction added with photo. The receipt text is added to the notes within about 10 seconds " +
      "(a few minutes if the backup reader is used); if you don't see it in Firefly yet, refresh the transaction page.");
    resetState();
    st.meta = await api("/api/meta");
    show("done");
  } catch (err) {
    $("confirm-msg").textContent = err.message;
    updateSave();
  }
});

$("btn-again").addEventListener("click", async () => {
  try { await enter(); } catch (_) { /* lock() handled */ }
});

// ---------- boot ----------
(async () => {
  try {
    const s = await (await fetch("/api/session", { credentials: "same-origin" })).json();
    st.idle = s.idle;
    if (s.unlocked) await enter(); else await showLock(true);
  } catch (_) {
    await showLock(true);
  }
})();
