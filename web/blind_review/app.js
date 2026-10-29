// Licensed under the Apache-2.0 license
// SPDX-License-Identifier: Apache-2.0

// TODO(security): Serverless static client-only review SPA hosted on Google Cloud Storage.
// Reviewer work emails and non-sensitive Yes/No card verdicts are stored in browser localStorage
// and synced via a short-lived GCS V4 Signed POST capability (GOOG4-RSA-SHA256) carried strictly
// in the private invite URL #auth= fragment (never stored in public GCS config.json, localStorage,
// query strings, or Referer headers) to a private write-only GCS dropbox bucket (Public Access
// Prevention enforced; signing Service Account holds only roles/storage.objectCreator: no read,
// no list, no delete/overwrite; policy restricts bucket, per-study key prefix, Content-Type, and
// byte size 2..61440). No session cookies, passwords, OAuth tokens, server-side CSRF endpoints,
// or SQL databases exist in this static architecture.

const STORAGE_PREFIX = "mjolnir_blind_v2";
const ACTIVE_EMAIL_PREFIX = "mjolnir_blind_active_email_v2";
const VALID_CARD_ID_RE = /^BF-\d{4}$/;
const VALID_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const VALID_BUCKET_RE = /^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$/;
const VALID_SLUG_RE = /^[a-zA-Z0-9._-]{1,64}$/;
const VALID_BATCH_NUM_RE = /^[1-9]\d?$/;
const VALID_SIGNED_POST_URL_RE =
  /^https:\/\/storage\.googleapis\.com\/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]\/$/;
const VALID_KEY_PREFIX_RE = /^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,126}\/$/;
const VALID_SAFE_FIELD_RE = /^[A-Za-z0-9+/=_.:@-]{1,4096}$/;
const VALID_HEX_SIG_RE = /^[0-9a-f]{128,2048}$/;
const VALID_B64URL_PART_RE = /^[A-Za-z0-9_-]{40,4096}$/;
const MAX_SNAPSHOT_BYTES = 56 * 1024;
const CLOUD_DEBOUNCE_MS = 700;

const state = {
  deck: null,
  allCards: [],
  cards: [],
  numBatches: 1,
  requestedBatch: 0,
  assignedBatch: 1,
  batchOrder: [],
  savedBatchOrder: [],
  priorityBatches: [],
  batchIdsByNum: new Map(),
  cardPosInBatch: new Map(),
  primaryBatchIds: new Set(),
  primaryBatchCount: 0,
  activeIndex: 0,
  reviewerEmail: "",
  sessionId: "",
  seq: 0,
  lastSyncedSeq: 0,
  reviews: {},
  signedPost: null,
  studyPrefix: "v2",
  studyKey: "default",
  activePocTab: "diff",
  sourceContextMode: "25",
  sourceLinesCache: new Map(),
  syncTimer: null,
  syncInFlight: false,
  retryAttempt: 0,
  autoAdvanceTimer: null,
};

function byId(id) {
  return document.getElementById(id);
}

function generateRandomHex(byteLen = 8) {
  const bytes = new Uint8Array(byteLen);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function generateSessionId() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return window.crypto.randomUUID();
  }
  return `${generateRandomHex(4)}-${generateRandomHex(2)}-${generateRandomHex(2)}-${generateRandomHex(2)}-${generateRandomHex(6)}`;
}

function normalizeEmail(raw) {
  const cleaned = String(raw || "")
    .trim()
    .toLowerCase()
    .slice(0, 120);
  return VALID_EMAIL_RE.test(cleaned) ? cleaned : "";
}

function maskEmailForDisplay(email) {
  const parts = String(email || "").split("@");
  if (parts.length !== 2) return "Email: --";
  const [local, domain] = parts;
  if (local.length <= 2) {
    return `${local.slice(0, 1)}***@${domain}`;
  }
  return `${local.slice(0, 1)}***${local.slice(-1)}@${domain}`;
}

function normalizeSeverity(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (s === "critical" || s === "crit") return "Critical";
  if (s === "high") return "High";
  if (s === "medium" || s === "med" || s === "moderate") return "Medium";
  if (s === "low") return "Low";
  if (s === "informational" || s === "info") return "Informational";
  return "";
}

function normalizeBinaryVerdict(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (s === "yes" || s === "y" || s === "tp" || s === "true_positive") return "Yes";
  if (s === "no" || s === "n" || s === "fp" || s === "false_positive") return "No";
  return "";
}

function isPass2() {
  return Boolean(state.deck && state.deck.pass === "pass2");
}

function getCardEntry(reviewId) {
  const entry = state.reviews[reviewId];
  if (!entry || typeof entry !== "object") {
    return { verdict: "", poc_demonstrates: "", updated_at: "" };
  }
  return entry;
}

function getCardBinaryChoice(reviewId) {
  const entry = getCardEntry(reviewId);
  if (isPass2()) {
    if (entry.poc_demonstrates === "yes") return "Yes";
    if (entry.poc_demonstrates === "no") return "No";
    return "";
  }
  return normalizeBinaryVerdict(entry.verdict);
}

function isCardCompleted(reviewId) {
  const choice = getCardBinaryChoice(reviewId);
  return choice === "Yes" || choice === "No";
}

function storageKeyFor(deckId, email) {
  return `${STORAGE_PREFIX}:${deckId}:${email}`;
}

function activeEmailKeyFor(deckId) {
  return `${ACTIVE_EMAIL_PREFIX}:${deckId}`;
}

function showNotice(message, isInfo = false) {
  const banner = byId("notice-banner");
  const textEl = byId("notice-banner-text");
  if (!banner || !textEl) return;
  textEl.textContent = String(message || "");
  banner.classList.toggle("info", Boolean(isInfo));
  banner.classList.remove("hidden");
}

function hideNotice() {
  const banner = byId("notice-banner");
  if (banner) banner.classList.add("hidden");
}

function formatClockTime(dateObj) {
  const hh = String(dateObj.getHours()).padStart(2, "0");
  const mm = String(dateObj.getMinutes()).padStart(2, "0");
  const ss = String(dateObj.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function setSaveStatusLabel(text, mode = "") {
  const el = byId("autosave-status-label");
  if (!el) return;
  el.textContent = text;
  el.classList.toggle("saved", mode === "saved");
  el.classList.toggle("saving", mode === "saving");
  el.classList.toggle("retrying", mode === "retrying");
}

function hashStringFnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i += 1) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function createSeededRng(seedStr) {
  let state32 = hashStringFnv1a(seedStr) || 0x6d2b79f5;
  return function nextFloat() {
    state32 = (state32 + 0x6d2b79f5) | 0;
    let t = Math.imul(state32 ^ (state32 >>> 15), 1 | state32);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffledInts(items, rng) {
  const arr = items.slice();
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

function sanitizeBatchOrder(rawArr, maxBatch) {
  if (!Array.isArray(rawArr) || rawArr.length !== maxBatch) return [];
  const seen = new Set();
  const out = [];
  for (const v of rawArr) {
    if (!Number.isInteger(v) || v < 1 || v > maxBatch || seen.has(v)) return [];
    seen.add(v);
    out.push(v);
  }
  return out;
}

function parseUrlHashParams() {
  const searchParams = new URLSearchParams(window.location.search);
  const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const getParam = (key) => hashParams.get(key) || searchParams.get(key) || "";
  const k = getParam("k");
  const rawBatch = getParam("batch") || getParam("s") || getParam("b");
  let batchNum = 0;
  if (VALID_BATCH_NUM_RE.test(rawBatch)) {
    const parsed = Number.parseInt(rawBatch, 10);
    if (parsed >= 1 && parsed <= 64) batchNum = parsed;
  }
  // Security: Only accept signed capabilities from the URL #fragment (never query strings).
  const rawAuth = hashParams.get("auth") || "";
  return {
    studyKey: VALID_SLUG_RE.test(k) ? k : "",
    requestedBatch: batchNum,
    authToken: rawAuth,
  };
}

function applyBatchRotation(email, savedOrder = []) {
  const allCards = Array.isArray(state.allCards) ? state.allCards : [];
  if (allCards.length === 0) {
    state.cards = [];
    state.numBatches = 1;
    state.assignedBatch = 1;
    state.batchOrder = [];
    state.batchIdsByNum = new Map();
    state.cardPosInBatch = new Map();
    state.primaryBatchIds = new Set();
    state.primaryBatchCount = 0;
    return;
  }

  let maxBatch = 0;
  for (const c of allCards) {
    if (Number.isInteger(c.batch) && c.batch >= 1 && c.batch <= 64 && c.batch > maxBatch) {
      maxBatch = c.batch;
    }
  }

  if (maxBatch <= 1) {
    state.numBatches = 1;
    state.assignedBatch = 1;
    state.batchOrder = [1];
    state.batchIdsByNum = new Map([[1, allCards.map((c) => c.review_id)]]);
    state.cardPosInBatch = new Map();
    allCards.forEach((c, idx) => {
      state.cardPosInBatch.set(c.review_id, {
        batch: 1,
        chunkRank: 1,
        idxInBatch: idx + 1,
        batchLen: allCards.length,
      });
    });
    state.cards = allCards.slice();
    state.primaryBatchIds = new Set(allCards.map((c) => c.review_id));
    state.primaryBatchCount = allCards.length;
    return;
  }

  state.numBatches = maxBatch;
  const byBatch = new Map();
  const unbatched = [];
  for (const c of allCards) {
    if (Number.isInteger(c.batch) && c.batch >= 1 && c.batch <= maxBatch) {
      if (!byBatch.has(c.batch)) byBatch.set(c.batch, []);
      byBatch.get(c.batch).push(c);
    } else {
      unbatched.push(c);
    }
  }

  let baseOrder = sanitizeBatchOrder(savedOrder, maxBatch);
  if (baseOrder.length !== maxBatch) {
    const deckKey = (state.deck && state.deck.deck_id) || "deck";
    const rng = createSeededRng(`${deckKey}:${email || "preview"}`);
    const prioSet = new Set();
    const prioList = [];
    for (const b of state.priorityBatches) {
      if (Number.isInteger(b) && b >= 1 && b <= maxBatch && byBatch.has(b) && !prioSet.has(b)) {
        prioSet.add(b);
        prioList.push(b);
      }
    }
    const restList = [];
    for (let b = 1; b <= maxBatch; b += 1) {
      if (!prioSet.has(b)) restList.push(b);
    }
    baseOrder = [...shuffledInts(prioList, rng), ...shuffledInts(restList, rng)];
    if (email) {
      state.savedBatchOrder = baseOrder.slice();
    }
  } else {
    state.savedBatchOrder = baseOrder.slice();
  }

  let effectiveOrder = baseOrder.slice();
  if (
    state.requestedBatch >= 1 &&
    state.requestedBatch <= maxBatch &&
    byBatch.has(state.requestedBatch)
  ) {
    effectiveOrder = [
      state.requestedBatch,
      ...baseOrder.filter((b) => b !== state.requestedBatch),
    ];
  }

  state.batchOrder = effectiveOrder;
  state.assignedBatch = effectiveOrder[0] || 1;
  state.batchIdsByNum = new Map();
  state.cardPosInBatch = new Map();

  const rotated = [];
  let primaryList = [];
  effectiveOrder.forEach((bNum, rankIdx) => {
    const group = byBatch.get(bNum) || [];
    if (rankIdx === 0) primaryList = group;
    state.batchIdsByNum.set(
      bNum,
      group.map((c) => c.review_id)
    );
    group.forEach((item, idxInB) => {
      state.cardPosInBatch.set(item.review_id, {
        batch: bNum,
        chunkRank: rankIdx + 1,
        idxInBatch: idxInB + 1,
        batchLen: group.length,
      });
      rotated.push(item);
    });
  });
  for (const item of unbatched) rotated.push(item);

  state.cards = rotated;
  state.primaryBatchIds = new Set(primaryList.map((c) => c.review_id));
  state.primaryBatchCount = primaryList.length > 0 ? primaryList.length : rotated.length;
}

function sanitizeStoredReviews(rawMap) {
  const cleaned = {};
  if (!rawMap || typeof rawMap !== "object") return cleaned;
  for (const [rid, val] of Object.entries(rawMap)) {
    if (!VALID_CARD_ID_RE.test(rid) || !val || typeof val !== "object") continue;
    const verdict = normalizeBinaryVerdict(val.verdict);
    const rawPoc = String(val.poc_demonstrates || "").toLowerCase();
    const pocDem = rawPoc === "yes" || rawPoc === "no" ? rawPoc : "";
    const updatedAt = String(val.updated_at || "").slice(0, 40);
    if (verdict || pocDem) {
      cleaned[rid] = { verdict, poc_demonstrates: pocDem, updated_at: updatedAt };
    }
  }
  return cleaned;
}

function persistLocalState() {
  if (!state.deck || !state.reviewerEmail) {
    setSaveStatusLabel("Enter email to start");
    return;
  }
  try {
    const payload = {
      schema_version: 2,
      deck_id: state.deck.deck_id,
      pass: state.deck.pass,
      reviewer_email: state.reviewerEmail,
      session_id: state.sessionId,
      batch_order: state.savedBatchOrder,
      seq: state.seq,
      last_synced_seq: state.lastSyncedSeq,
      saved_at: new Date().toISOString(),
      reviews: state.reviews,
    };
    window.localStorage.setItem(
      storageKeyFor(state.deck.deck_id, state.reviewerEmail),
      JSON.stringify(payload)
    );
    window.localStorage.setItem(activeEmailKeyFor(state.deck.deck_id), state.reviewerEmail);
  } catch (_err) {
    setSaveStatusLabel("Browser storage unavailable", "retrying");
    showNotice("Browser localStorage is unavailable; keep this tab open until answers finish syncing.");
  }
}

function loadStateForEmail(email) {
  if (!state.deck || !email) {
    state.reviews = {};
    state.sessionId = generateSessionId();
    state.savedBatchOrder = [];
    state.seq = 0;
    state.lastSyncedSeq = 0;
    return;
  }
  try {
    const raw = window.localStorage.getItem(storageKeyFor(state.deck.deck_id, email));
    if (!raw) {
      state.reviews = {};
      state.sessionId = generateSessionId();
      state.savedBatchOrder = [];
      state.seq = 0;
      state.lastSyncedSeq = 0;
      return;
    }
    const parsed = JSON.parse(raw);
    state.reviews = sanitizeStoredReviews(parsed && parsed.reviews);
    state.sessionId =
      parsed && typeof parsed.session_id === "string" && VALID_SLUG_RE.test(parsed.session_id)
        ? parsed.session_id
        : generateSessionId();
    state.savedBatchOrder = Array.isArray(parsed && parsed.batch_order)
      ? parsed.batch_order.filter((n) => Number.isInteger(n) && n >= 1 && n <= 64)
      : [];
    state.seq =
      parsed && Number.isInteger(parsed.seq) && parsed.seq >= 0 ? parsed.seq : 0;
    state.lastSyncedSeq =
      parsed && Number.isInteger(parsed.last_synced_seq) && parsed.last_synced_seq >= 0
        ? parsed.last_synced_seq
        : 0;
  } catch (_err) {
    state.reviews = {};
    state.sessionId = generateSessionId();
    state.savedBatchOrder = [];
    state.seq = 0;
    state.lastSyncedSeq = 0;
  }
}

// --- Write-Only GCS Cloud Dropbox Autosave ---

function hasCloudSyncConfigured() {
  return Boolean(state.signedPost);
}

function validateSignedPostConfig(rawSp) {
  if (!rawSp || typeof rawSp !== "object") return null;
  if (typeof rawSp.url !== "string" || !VALID_SIGNED_POST_URL_RE.test(rawSp.url)) return null;
  if (
    typeof rawSp.key_prefix !== "string" ||
    !VALID_KEY_PREFIX_RE.test(rawSp.key_prefix) ||
    rawSp.key_prefix.split("/").includes("..")
  ) {
    return null;
  }
  const f = rawSp.fields;
  if (!f || typeof f !== "object") return null;
  const requiredFields = [
    "Content-Type",
    "success_action_status",
    "x-goog-algorithm",
    "x-goog-credential",
    "x-goog-date",
    "policy",
  ];
  const cleanedFields = {};
  for (const name of requiredFields) {
    if (typeof f[name] !== "string" || !VALID_SAFE_FIELD_RE.test(f[name])) return null;
    cleanedFields[name] = f[name];
  }
  if (
    typeof f["x-goog-signature"] !== "string" ||
    !VALID_HEX_SIG_RE.test(f["x-goog-signature"])
  ) {
    return null;
  }
  cleanedFields["x-goog-signature"] = f["x-goog-signature"];
  if (cleanedFields["Content-Type"] !== "application/json") return null;
  if (cleanedFields["x-goog-algorithm"] !== "GOOG4-RSA-SHA256") return null;

  return {
    url: rawSp.url,
    keyPrefix: rawSp.key_prefix,
    expiresAt: typeof rawSp.expires_at === "string" ? rawSp.expires_at.slice(0, 40) : "",
    fields: cleanedFields,
  };
}

function b64UrlToStandardB64(b64url) {
  const std = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (std.length % 4)) % 4;
  return std + "=".repeat(padLen);
}

function parseSignedAuthToken(rawToken) {
  if (typeof rawToken !== "string" || rawToken.length < 100 || rawToken.length > 6000) {
    return null;
  }
  const parts = rawToken.trim().split(".");
  if (parts.length !== 2) return null;
  const [polUrl, sigUrl] = parts;
  if (!VALID_B64URL_PART_RE.test(polUrl) || !VALID_B64URL_PART_RE.test(sigUrl)) {
    return null;
  }
  try {
    const policyB64 = b64UrlToStandardB64(polUrl);
    const sigBin = window.atob(b64UrlToStandardB64(sigUrl));
    if (sigBin.length < 64 || sigBin.length > 1024) return null;
    let hexSig = "";
    for (let i = 0; i < sigBin.length; i += 1) {
      hexSig += sigBin.charCodeAt(i).toString(16).padStart(2, "0");
    }

    const decodedJson = window.atob(policyB64);
    const doc = JSON.parse(decodedJson);
    if (!doc || typeof doc !== "object" || !Array.isArray(doc.conditions)) return null;

    let bucket = "";
    let keyPrefix = "";
    const fields = {
      policy: policyB64,
      "x-goog-signature": hexSig,
    };
    for (const cond of doc.conditions) {
      if (Array.isArray(cond) && cond.length === 3) {
        if (cond[0] === "starts-with" && cond[1] === "$key" && typeof cond[2] === "string") {
          keyPrefix = cond[2];
        }
      } else if (cond && typeof cond === "object") {
        for (const [k, v] of Object.entries(cond)) {
          if (typeof v !== "string") continue;
          if (k === "bucket") bucket = v;
          else if (
            k === "Content-Type" ||
            k === "success_action_status" ||
            k === "x-goog-algorithm" ||
            k === "x-goog-credential" ||
            k === "x-goog-date"
          ) {
            fields[k] = v;
          }
        }
      }
    }
    if (!VALID_BUCKET_RE.test(bucket)) return null;
    return validateSignedPostConfig({
      url: `https://storage.googleapis.com/${bucket}/`,
      expires_at: typeof doc.expiration === "string" ? doc.expiration : "",
      key_prefix: keyPrefix,
      fields,
    });
  } catch (_err) {
    return null;
  }
}

function buildCloudSnapshotPayload(targetSeq) {
  let completedCount = 0;
  for (const card of state.cards) {
    if (isCardCompleted(card.review_id)) completedCount += 1;
  }
  return {
    schema_version: 2,
    study_key: VALID_SLUG_RE.test(state.studyKey) ? state.studyKey : "default",
    deck_id: state.deck.deck_id,
    pass: state.deck.pass || "pass1",
    project_name: state.deck.project_name || "",
    repo_name: state.deck.repo_name || "",
    pinned_rev: state.deck.pinned_rev || "",
    reviewer_email: state.reviewerEmail,
    session_id: state.sessionId,
    assigned_batch: state.assignedBatch,
    batch_order: state.batchOrder,
    seq: targetSeq,
    saved_at: new Date().toISOString(),
    completed_count: completedCount,
    total_count: state.cards.length,
    reviews: state.reviews,
  };
}

async function postSignedSnapshot(sp, deckSlug, targetSeq, fileBlob, useKeepalive) {
  const seqPad = String(targetSeq).padStart(6, "0");
  const objectKey = `${sp.keyPrefix}${deckSlug}/${state.sessionId}/${seqPad}_${generateRandomHex(8)}.json`;
  const form = new FormData();
  form.append("key", objectKey);
  form.append("Content-Type", sp.fields["Content-Type"]);
  form.append("success_action_status", sp.fields.success_action_status);
  form.append("x-goog-algorithm", sp.fields["x-goog-algorithm"]);
  form.append("x-goog-credential", sp.fields["x-goog-credential"]);
  form.append("x-goog-date", sp.fields["x-goog-date"]);
  form.append("policy", sp.fields.policy);
  form.append("x-goog-signature", sp.fields["x-goog-signature"]);
  // GCS XML POST Object requires 'file' to be the final form field.
  form.append("file", fileBlob, "snapshot.json");
  return fetch(sp.url, {
    method: "POST",
    body: form,
    keepalive: Boolean(useKeepalive),
  });
}

async function flushCloudSync(useKeepalive = false) {
  window.clearTimeout(state.syncTimer);
  state.syncTimer = null;

  if (!state.deck || !state.reviewerEmail) return;
  if (!hasCloudSyncConfigured()) {
    setSaveStatusLabel(`Saved \u2022 ${formatClockTime(new Date())}`, "saved");
    return;
  }
  if (state.seq <= state.lastSyncedSeq) {
    setSaveStatusLabel("All changes saved", "saved");
    return;
  }
  if (state.syncInFlight && !useKeepalive) return;

  const targetSeq = state.seq;
  const bodyStr = JSON.stringify(buildCloudSnapshotPayload(targetSeq));
  const fileBlob = new Blob([bodyStr], { type: "application/json" });
  if (fileBlob.size < 2 || fileBlob.size > MAX_SNAPSHOT_BYTES) {
    setSaveStatusLabel("Saved locally", "retrying");
    return;
  }

  const deckSlug = String(state.deck.deck_id || "deck").replace(/[^a-zA-Z0-9._-]/g, "-").slice(0, 64);

  state.syncInFlight = true;
  setSaveStatusLabel("Saving\u2026", "saving");

  try {
    const res = await postSignedSnapshot(
      state.signedPost,
      deckSlug,
      targetSeq,
      fileBlob,
      useKeepalive,
    );
    if (!res.ok) {
      if (res.status === 400 || res.status === 403) {
        const expMs = state.signedPost.expiresAt ? Date.parse(state.signedPost.expiresAt) : NaN;
        if (!Number.isNaN(expMs) && expMs <= Date.now()) {
          showNotice(
            `This signed review link expired (${state.signedPost.expiresAt}). Answers remain saved in your browser — please ask the coordinator for an updated signed link.`,
          );
          setSaveStatusLabel("Link expired (saved locally)", "retrying");
          return;
        }
      }
      throw new Error(`HTTP ${res.status}`);
    }
    state.retryAttempt = 0;
    if (targetSeq > state.lastSyncedSeq) {
      state.lastSyncedSeq = targetSeq;
      persistLocalState();
    }
    if (state.seq > state.lastSyncedSeq) {
      scheduleCloudSync(250);
    } else {
      setSaveStatusLabel("All changes saved", "saved");
    }
  } catch (_err) {
    state.retryAttempt += 1;
    setSaveStatusLabel("Saved locally \u2022 Cloud sync queued", "retrying");
    const backoffMs = Math.min(30000, 3000 * state.retryAttempt);
    window.clearTimeout(state.syncTimer);
    state.syncTimer = window.setTimeout(() => {
      flushCloudSync(false);
    }, backoffMs);
  } finally {
    state.syncInFlight = false;
  }
}

function scheduleCloudSync(delayMs = CLOUD_DEBOUNCE_MS) {
  if (!hasCloudSyncConfigured()) {
    setSaveStatusLabel(`Saved \u2022 ${formatClockTime(new Date())}`, "saved");
    return;
  }
  setSaveStatusLabel("Saving\u2026", "saving");
  window.clearTimeout(state.syncTimer);
  state.syncTimer = window.setTimeout(() => {
    flushCloudSync(false);
  }, delayMs);
}

// --- Safe DOM Rendering (Zero innerHTML) ---

function appendInlineFormattedText(parentEl, text) {
  const tokenRe = /(`[^`\n]+`|\*\*[^*\n]+\*\*)/g;
  let lastIdx = 0;
  let match;
  while ((match = tokenRe.exec(text)) !== null) {
    if (match.index > lastIdx) {
      parentEl.appendChild(document.createTextNode(text.slice(lastIdx, match.index)));
    }
    const tok = match[0];
    if (tok.startsWith("`") && tok.endsWith("`")) {
      const codeEl = document.createElement("code");
      codeEl.className = "inline-code";
      codeEl.textContent = tok.slice(1, -1);
      parentEl.appendChild(codeEl);
    } else if (tok.startsWith("**") && tok.endsWith("**")) {
      const strongEl = document.createElement("strong");
      strongEl.textContent = tok.slice(2, -2);
      parentEl.appendChild(strongEl);
    } else {
      parentEl.appendChild(document.createTextNode(tok));
    }
    lastIdx = tokenRe.lastIndex;
  }
  if (lastIdx < text.length) {
    parentEl.appendChild(document.createTextNode(text.slice(lastIdx)));
  }
}

function renderSafeRichText(container, rawText) {
  container.replaceChildren();
  const text = String(rawText || "").trim();
  if (!text) {
    const emptyP = document.createElement("p");
    emptyP.textContent = "None provided.";
    container.appendChild(emptyP);
    return;
  }

  const fenceRe = /```(?:[a-zA-Z0-9_+-]+)?\r?\n([\s\S]*?)```/g;
  let cursor = 0;
  let fenceMatch;

  const appendProseChunk = (prose) => {
    const paragraphs = prose
      .split(/\n{2,}/)
      .map((p) => p.trim())
      .filter(Boolean);
    for (const para of paragraphs) {
      const pEl = document.createElement("p");
      const lines = para.split("\n");
      lines.forEach((line, idx) => {
        if (idx > 0) pEl.appendChild(document.createElement("br"));
        appendInlineFormattedText(pEl, line);
      });
      container.appendChild(pEl);
    }
  };

  while ((fenceMatch = fenceRe.exec(text)) !== null) {
    if (fenceMatch.index > cursor) {
      appendProseChunk(text.slice(cursor, fenceMatch.index));
    }
    const preEl = document.createElement("pre");
    preEl.className = "code-block";
    const codeEl = document.createElement("code");
    codeEl.textContent = fenceMatch[1].replace(/\s+$/, "");
    preEl.appendChild(codeEl);
    container.appendChild(preEl);
    cursor = fenceRe.lastIndex;
  }

  if (cursor < text.length) {
    appendProseChunk(text.slice(cursor));
  }
}

function getSourceLinesForFile(filePath) {
  const clean = String(filePath || "").replace(/^\/+/, "");
  if (state.sourceLinesCache.has(clean)) {
    return state.sourceLinesCache.get(clean);
  }
  const filesMap = state.deck && state.deck.source_files;
  if (!filesMap || typeof filesMap !== "object" || typeof filesMap[clean] !== "string") {
    return null;
  }
  const lines = filesMap[clean].split(/\r?\n/);
  state.sourceLinesCache.set(clean, lines);
  return lines;
}

function renderCardSourceSnippet(card) {
  const secEl = byId("section-source-snippet");
  const scrollEl = byId("card-source-scroll");
  const rangeEl = byId("source-range-label");
  if (!secEl || !scrollEl || !rangeEl) return;

  const lines = getSourceLinesForFile(card.file);
  if (!lines || lines.length === 0) {
    secEl.classList.add("hidden");
    scrollEl.replaceChildren();
    return;
  }

  secEl.classList.remove("hidden");
  const total = lines.length;
  const focusStart = card.start_line && card.start_line >= 1 ? Math.min(total, card.start_line) : 1;
  const focusEnd =
    card.end_line && card.end_line >= focusStart
      ? Math.min(total, card.end_line)
      : Math.min(total, focusStart + 15);

  let winStart = 1;
  let winEnd = total;
  if (state.sourceContextMode !== "full") {
    const radius = state.sourceContextMode === "80" ? 80 : 25;
    winStart = Math.max(1, focusStart - radius);
    winEnd = Math.min(total, focusEnd + radius);
  }

  for (const mode of ["25", "80", "full"]) {
    const b = byId(`btn-src-ctx-${mode}`);
    if (b) b.classList.toggle("active", state.sourceContextMode === mode);
  }
  scrollEl.classList.toggle("full-height", state.sourceContextMode === "full");
  rangeEl.textContent = `L${winStart}\u2013L${winEnd} of ${total} \u2022 Focus L${focusStart}\u2013L${focusEnd}`;

  const frag = document.createDocumentFragment();
  let firstHighlightEl = null;
  for (let ln = winStart; ln <= winEnd; ln += 1) {
    const row = document.createElement("div");
    const isHit = ln >= focusStart && ln <= focusEnd;
    row.className = isHit ? "src-line highlighted" : "src-line";

    const numSpan = document.createElement("span");
    numSpan.className = "src-ln";
    numSpan.textContent = String(ln);

    const codeSpan = document.createElement("span");
    codeSpan.className = "src-code";
    codeSpan.textContent = lines[ln - 1] || " ";

    row.appendChild(numSpan);
    row.appendChild(codeSpan);
    frag.appendChild(row);
    if (isHit && !firstHighlightEl) {
      firstHighlightEl = row;
    }
  }
  scrollEl.replaceChildren(frag);

  window.requestAnimationFrame(() => {
    scrollEl.scrollTop = firstHighlightEl ? Math.max(0, firstHighlightEl.offsetTop - 90) : 0;
  });
}

function getCardPocField(card, tabKey) {
  if (!card) return "";
  if (tabKey === "diff") return card.poc_patch_diff || "";
  if (tabKey === "repro") return card.reproduce_sh || "";
  if (tabKey === "log") return card.harness_log_tail || "";
  return card.poc_summary || "";
}

function cardHasPocArtifacts(card) {
  return Boolean(
    card && (card.poc_patch_diff || card.reproduce_sh || card.harness_log_tail || card.poc_summary),
  );
}

function renderPass2PocTabContent(card) {
  const preEl = byId("card-poc-artifact-pre");
  if (!preEl) return;
  let content = "";
  if (state.activePocTab === "diff") {
    content = card.poc_patch_diff || "(No poc_patch.diff recorded)";
  } else if (state.activePocTab === "repro") {
    content = card.reproduce_sh || "(No reproduce.sh recorded)";
  } else if (state.activePocTab === "log") {
    content = card.harness_log_tail || "(No harness_commands.log tail recorded)";
  } else {
    content = card.poc_summary || "(No PoC summary text recorded)";
  }
  preEl.textContent = content;

  for (const tabKey of ["diff", "repro", "log", "summary"]) {
    const btn = byId(`btn-poc-tab-${tabKey}`);
    if (btn) btn.classList.toggle("active", state.activePocTab === tabKey);
  }
}

function updateTopbarProgress() {
  const total = state.cards.length;
  let completed = 0;
  for (const card of state.cards) {
    if (isCardCompleted(card.review_id)) {
      completed += 1;
    }
  }

  const multiBatch = state.numBatches > 1 && state.batchOrder.length > 1;
  let completedChunks = 0;
  if (multiBatch) {
    for (const bNum of state.batchOrder) {
      const rids = state.batchIdsByNum.get(bNum) || [];
      if (rids.length > 0 && rids.every((rid) => isCardCompleted(rid))) {
        completedChunks += 1;
      }
    }
  }

  const activeCard = state.cards[state.activeIndex];
  const activeMeta = activeCard ? state.cardPosInBatch.get(activeCard.review_id) : null;
  let curRank = 1;
  let curBatchDone = completed;
  let curBatchLen = total;
  if (multiBatch && activeMeta) {
    curRank = activeMeta.chunkRank;
    const rids = state.batchIdsByNum.get(activeMeta.batch) || [];
    curBatchLen = rids.length || 1;
    curBatchDone = rids.reduce((acc, rid) => acc + (isCardCompleted(rid) ? 1 : 0), 0);
  }

  let denom = total;
  let numer = completed;
  if (multiBatch && completed < total) {
    denom = curBatchLen;
    numer = curBatchDone;
  }
  const pct = denom > 0 ? Math.min(100, Math.round((numer / denom) * 1000) / 10) : 0;
  const rect = byId("progress-rect");
  if (rect) rect.setAttribute("width", String(pct));

  const labelEl = byId("progress-count-label");
  if (labelEl) {
    if (multiBatch) {
      if (total > 0 && completed === total) {
        labelEl.textContent = `All ${total} reviewed`;
      } else if (completed > curBatchDone) {
        labelEl.textContent = `Chunk ${curRank}: ${curBatchDone} / ${curBatchLen} (${completed} total)`;
      } else {
        labelEl.textContent = `Chunk ${curRank}: ${curBatchDone} / ${curBatchLen}`;
      }
    } else {
      labelEl.textContent = `${completed} / ${total}`;
    }
  }

  const doneBanner = byId("completion-banner");
  if (doneBanner) {
    if (total > 0 && completed === total) {
      doneBanner.textContent =
        "All findings reviewed \u2014 your answers are saved automatically. Thank you!";
      doneBanner.classList.remove("hidden");
    } else if (multiBatch && completedChunks >= 1) {
      doneBanner.textContent =
        completedChunks === 1
          ? `1 chunk complete (${completed} reviewed) \u2014 saved! Stop here anytime, or tackle a 2nd chunk (~${curBatchLen} findings) below.`
          : `${completedChunks} chunks complete (${completed} reviewed) \u2014 saved! Stop here anytime, or keep going below.`;
      doneBanner.classList.remove("hidden");
    } else {
      doneBanner.classList.add("hidden");
    }
  }
}

function renderActiveCard() {
  if (state.cards.length === 0 || !state.cards[state.activeIndex]) {
    byId("card-title-heading").textContent = "No findings in this deck.";
    return;
  }

  const card = state.cards[state.activeIndex];
  const choice = getCardBinaryChoice(card.review_id);
  const posMeta = state.cardPosInBatch.get(card.review_id);

  if (state.numBatches > 1 && posMeta) {
    byId("card-position-pill").textContent =
      `Chunk ${posMeta.chunkRank} (Batch ${posMeta.batch}) \u2022 Finding ${posMeta.idxInBatch} of ${posMeta.batchLen}`;
  } else {
    byId("card-position-pill").textContent = `Finding ${state.activeIndex + 1} of ${state.cards.length}`;
  }

  const sevNorm = normalizeSeverity(card.reported_severity) || "Medium";
  const sevBadge = byId("card-sev-badge");
  sevBadge.className = `badge-sev badge-sev-${sevNorm}`;
  sevBadge.textContent = sevNorm;

  byId("card-cwe-pill").textContent = card.cwe || "Unclassified CWE";

  const verdictPill = byId("card-current-verdict-pill");
  verdictPill.textContent = choice ? `Answered: ${choice}` : "Unanswered";

  byId("card-title-heading").textContent = card.title || "Untitled Finding";
  byId("card-location-code").textContent = card.location
    ? `${card.file} (${card.location})`
    : card.file;

  const ghLink = byId("card-github-link");
  if (typeof card.source_url === "string" && card.source_url.startsWith("https://github.com/")) {
    ghLink.setAttribute("href", card.source_url);
    ghLink.classList.remove("hidden");
  } else {
    ghLink.classList.add("hidden");
  }

  renderCardSourceSnippet(card);
  renderSafeRichText(byId("card-description-content"), card.description);

  const avSec = byId("section-attack-vector");
  if (card.attack_vector) {
    renderSafeRichText(byId("card-attack-vector-content"), card.attack_vector);
    avSec.classList.remove("hidden");
  } else {
    avSec.classList.add("hidden");
  }

  const recSec = byId("section-recommendation");
  if (card.recommendation) {
    renderSafeRichText(byId("card-recommendation-content"), card.recommendation);
    recSec.classList.remove("hidden");
  } else {
    recSec.classList.add("hidden");
  }

  const pocSec = byId("section-pass2-poc");
  if (isPass2() || cardHasPocArtifacts(card)) {
    pocSec.classList.remove("hidden");
    if (!getCardPocField(card, state.activePocTab)) {
      const firstAvail = ["diff", "repro", "log", "summary"].find((t) =>
        Boolean(getCardPocField(card, t)),
      );
      if (firstAvail) {
        state.activePocTab = firstAvail;
      }
    }
    renderPass2PocTabContent(card);
  } else {
    pocSec.classList.add("hidden");
  }

  byId("grade-question-heading").textContent = isPass2()
    ? "Does this PoC faithfully exercise the claimed bug?"
    : "Is this a security-relevant bug?";
  byId("grade-helper-text").textContent = isPass2()
    ? "Yes = The PoC exercises the claimed root cause without modifying production logic. No = Fails for an unrelated setup reason or tests a tautology."
    : "Yes = Security-relevant bug under the project\u2019s threat model. No = Prevented by existing checks/countermeasures, non-security issue, or outside the threat model.";

  byId("btn-answer-yes").classList.toggle("active-yes", choice === "Yes");
  byId("btn-answer-no").classList.toggle("active-no", choice === "No");

  byId("btn-prev-card").disabled = state.activeIndex <= 0;
  byId("btn-next-card").disabled = state.activeIndex >= state.cards.length - 1;
}

function refreshView() {
  updateTopbarProgress();
  renderActiveCard();
}

function findNextUnansweredFrom(startIdx) {
  const n = state.cards.length;
  for (let offset = 1; offset < n; offset += 1) {
    const idx = (startIdx + offset) % n;
    if (!isCardCompleted(state.cards[idx].review_id)) return idx;
  }
  return -1;
}

function setBinaryAnswer(choice) {
  const card = state.cards[state.activeIndex];
  if (!card) return;
  if (!state.reviewerEmail) {
    openEmailModal();
    return;
  }

  const prev = getCardEntry(card.review_id);
  state.reviews[card.review_id] = {
    verdict: isPass2() ? prev.verdict || "" : choice,
    poc_demonstrates: isPass2() ? (choice === "Yes" ? "yes" : "no") : prev.poc_demonstrates || "",
    updated_at: new Date().toISOString(),
  };

  state.seq += 1;
  persistLocalState();
  scheduleCloudSync();
  refreshView();

  window.clearTimeout(state.autoAdvanceTimer);
  state.autoAdvanceTimer = window.setTimeout(() => {
    const nextUnanswered = findNextUnansweredFrom(state.activeIndex);
    if (nextUnanswered >= 0) {
      state.activeIndex = nextUnanswered;
      refreshView();
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else if (state.activeIndex < state.cards.length - 1) {
      state.activeIndex += 1;
      refreshView();
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }, 160);
}

function stepCard(delta) {
  if (state.cards.length === 0) return;
  const nextIdx = Math.max(0, Math.min(state.cards.length - 1, state.activeIndex + delta));
  if (nextIdx === state.activeIndex) return;
  state.activeIndex = nextIdx;
  renderActiveCard();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function openEmailModal() {
  const overlay = byId("email-modal-overlay");
  const input = byId("input-reviewer-email");
  const errEl = byId("email-form-error");
  const cancelBtn = byId("btn-cancel-email");
  const clearBtn = byId("btn-clear-session");
  if (errEl) errEl.textContent = "";
  if (input) input.value = "";
  const hasActive = Boolean(state.reviewerEmail);
  if (cancelBtn) cancelBtn.classList.toggle("hidden", !hasActive);
  if (clearBtn) clearBtn.classList.toggle("hidden", !hasActive);
  if (overlay) overlay.classList.remove("hidden");
  if (input) input.focus();
}

function closeEmailModal() {
  const overlay = byId("email-modal-overlay");
  if (overlay) overlay.classList.add("hidden");
}

function clearActiveSessionAndReload() {
  try {
    if (state.deck && state.deck.deck_id) {
      window.localStorage.removeItem(activeEmailKeyFor(state.deck.deck_id));
    }
  } catch (_err) {
    // Ignore storage removal errors.
  }
  state.reviewerEmail = "";
  state.reviews = {};
  state.sessionId = "";
  state.savedBatchOrder = [];
  state.seq = 0;
  state.lastSyncedSeq = 0;
  window.location.reload();
}

function applyReviewerEmail(rawInput) {
  const email = normalizeEmail(rawInput);
  const errEl = byId("email-form-error");
  if (!email) {
    if (errEl) {
      errEl.textContent = "Please enter a valid work email address (e.g., name@company.com).";
    }
    return false;
  }
  state.reviewerEmail = email;
  byId("active-email-pill").textContent = maskEmailForDisplay(email);
  loadStateForEmail(email);
  applyBatchRotation(email, state.savedBatchOrder);
  persistLocalState();

  if (state.seq > state.lastSyncedSeq) {
    scheduleCloudSync(150);
  } else if (hasCloudSyncConfigured() && state.seq > 0) {
    setSaveStatusLabel("All changes saved", "saved");
  } else {
    setSaveStatusLabel(`Saved \u2022 ${formatClockTime(new Date())}`, "saved");
  }

  closeEmailModal();

  const firstUnanswered = state.cards.findIndex((c) => !isCardCompleted(c.review_id));
  state.activeIndex = firstUnanswered >= 0 ? firstUnanswered : 0;
  refreshView();
  return true;
}

function wireEvents() {
  byId("btn-dismiss-notice").addEventListener("click", hideNotice);
  byId("btn-switch-email").addEventListener("click", openEmailModal);
  byId("btn-cancel-email").addEventListener("click", closeEmailModal);
  byId("btn-clear-session").addEventListener("click", clearActiveSessionAndReload);

  byId("form-email-entry").addEventListener("submit", (e) => {
    e.preventDefault();
    applyReviewerEmail(byId("input-reviewer-email").value);
  });

  byId("btn-toggle-tm").addEventListener("click", () => {
    const drawer = byId("threat-model-drawer");
    const isNowHidden = drawer.classList.toggle("hidden");
    byId("btn-toggle-tm").setAttribute("aria-expanded", String(!isNowHidden));
  });
  byId("btn-close-tm").addEventListener("click", () => {
    byId("threat-model-drawer").classList.add("hidden");
    byId("btn-toggle-tm").setAttribute("aria-expanded", "false");
  });

  byId("btn-answer-yes").addEventListener("click", () => setBinaryAnswer("Yes"));
  byId("btn-answer-no").addEventListener("click", () => setBinaryAnswer("No"));
  byId("btn-prev-card").addEventListener("click", () => stepCard(-1));
  byId("btn-next-card").addEventListener("click", () => stepCard(1));

  for (const ctxMode of ["25", "80", "full"]) {
    byId(`btn-src-ctx-${ctxMode}`).addEventListener("click", () => {
      state.sourceContextMode = ctxMode;
      if (state.cards[state.activeIndex]) {
        renderCardSourceSnippet(state.cards[state.activeIndex]);
      }
    });
  }

  for (const tabKey of ["diff", "repro", "log", "summary"]) {
    byId(`btn-poc-tab-${tabKey}`).addEventListener("click", () => {
      state.activePocTab = tabKey;
      if (state.cards[state.activeIndex]) {
        renderPass2PocTabContent(state.cards[state.activeIndex]);
      }
    });
  }

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") flushCloudSync(true);
  });
  window.addEventListener("pagehide", () => flushCloudSync(true));
  window.addEventListener("online", () => {
    if (state.seq > state.lastSyncedSeq) flushCloudSync(false);
  });
  window.addEventListener("hashchange", () => {
    const hashCfg = parseUrlHashParams();
    if (hashCfg.studyKey) state.studyKey = hashCfg.studyKey;
    state.requestedBatch = hashCfg.requestedBatch;
    if (hashCfg.authToken) {
      const parsedSp = parseSignedAuthToken(hashCfg.authToken);
      if (parsedSp) {
        state.signedPost = parsedSp;
        hideNotice();
        if (state.seq > state.lastSyncedSeq) scheduleCloudSync(150);
      }
    }
    if (state.deck) {
      applyBatchRotation(state.reviewerEmail, state.savedBatchOrder);
      const firstUnanswered = state.cards.findIndex((c) => !isCardCompleted(c.review_id));
      state.activeIndex = firstUnanswered >= 0 ? firstUnanswered : 0;
      refreshView();
    }
  });

  window.addEventListener("keydown", (e) => {
    const modalOpen = !byId("email-modal-overlay").classList.contains("hidden");
    if (modalOpen) return;
    const tag = document.activeElement ? document.activeElement.tagName : "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    const k = e.key;
    if (k === "y" || k === "Y" || k === "t" || k === "T") {
      e.preventDefault();
      setBinaryAnswer("Yes");
    } else if (k === "n" || k === "N" || k === "f" || k === "F") {
      e.preventDefault();
      setBinaryAnswer("No");
    }
  });
}

async function loadOptionalConfig() {
  try {
    const res = await fetch("./config.json", { cache: "no-store" });
    if (!res.ok) return;
    const cfg = await res.json();
    if (!cfg || typeof cfg !== "object") return;
    // Security: Cloud upload credentials are accepted exclusively from #auth= in the private invite URL,
    // never from publicly readable config.json objects.
    if (typeof cfg.study_prefix === "string" && VALID_SLUG_RE.test(cfg.study_prefix)) {
      state.studyPrefix = cfg.study_prefix;
    }
    if (typeof cfg.default_study_key === "string" && VALID_SLUG_RE.test(cfg.default_study_key)) {
      state.studyKey = cfg.default_study_key;
    }
    if (Array.isArray(cfg.priority_batches)) {
      const seen = new Set();
      const prio = [];
      for (const n of cfg.priority_batches) {
        if (Number.isInteger(n) && n >= 1 && n <= 64 && !seen.has(n)) {
          seen.add(n);
          prio.push(n);
        }
      }
      state.priorityBatches = prio;
    }
  } catch (_err) {
    // Optional config.json may be absent in standalone local previews.
  }
}

async function initApp() {
  wireEvents();
  await loadOptionalConfig();

  const hashCfg = parseUrlHashParams();
  if (hashCfg.studyKey) state.studyKey = hashCfg.studyKey;
  if (hashCfg.requestedBatch > 0) state.requestedBatch = hashCfg.requestedBatch;
  if (hashCfg.authToken) {
    const parsedSp = parseSignedAuthToken(hashCfg.authToken);
    if (parsedSp) {
      state.signedPost = parsedSp;
      const expMs = parsedSp.expiresAt ? Date.parse(parsedSp.expiresAt) : NaN;
      if (!Number.isNaN(expMs) && expMs <= Date.now()) {
        showNotice(
          `This signed invite link expired (${parsedSp.expiresAt}). Answers save in this browser — please request a fresh link to upload responses.`,
        );
      }
    } else {
      showNotice(
        "The signed upload token (#auth=...) in this link appears truncated or invalid. Please open the full unmodified invite link.",
      );
    }
  } else if (window.location.hostname.endsWith("googleapis.com")) {
    showNotice(
      "Local-only preview (opened without signed #auth=... token) — answers save in this browser only and will not sync to cloud storage.",
      true,
    );
  }

  try {
    const res = await fetch("./deck.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const deck = await res.json();
    if (!deck || !Array.isArray(deck.cards)) throw new Error("Malformed deck.json");

    state.deck = deck;
    state.allCards = deck.cards;
    applyBatchRotation("");

    const modalDescEl = byId("email-modal-desc");
    if (modalDescEl) {
      if (state.numBatches > 1) {
        const approxPerChunk = Math.max(1, Math.round(state.allCards.length / state.numBatches));
        modalDescEl.textContent =
          `Enter your work email to begin. Findings are grouped by source file into ~${approxPerChunk}-finding chunks (starting at a random chunk) \u2014 try 1\u20132 chunks or stop whenever you like; every answer saves automatically.`;
      } else {
        modalDescEl.textContent =
          `Enter your work email to begin reviewing these ${state.allCards.length} findings (grouped by source file). Stop whenever you like \u2014 every answer saves automatically.`;
      }
    }

    byId("deck-title").textContent = deck.repo_name
      ? `Mjolnir Security Review \u2014 ${deck.repo_name}`
      : "Mjolnir Security Review";
    const shortRev = deck.pinned_rev ? String(deck.pinned_rev).slice(0, 12) : "pinned";
    byId("target-commit-pill").textContent = `${deck.repo_name || "repo"} @ ${shortRev}`;

    const treeLink = byId("repo-tree-link");
    if (typeof deck.repo_tree_url === "string" && deck.repo_tree_url.startsWith("https://github.com/")) {
      treeLink.setAttribute("href", deck.repo_tree_url);
      treeLink.classList.remove("hidden");
    }

    byId("threat-model-content").textContent =
      deck.threat_model_markdown || "No repository threat model markdown attached to this deck.";

    let savedEmail = "";
    try {
      savedEmail = normalizeEmail(window.localStorage.getItem(activeEmailKeyFor(deck.deck_id)));
    } catch (_err) {
      savedEmail = "";
    }

    if (savedEmail) {
      applyReviewerEmail(savedEmail);
    } else {
      refreshView();
      openEmailModal();
    }
  } catch (_err) {
    byId("card-title-heading").textContent = "Unable to load review deck (./deck.json).";
    showNotice("Could not fetch ./deck.json. Verify you are opening index.html over HTTP(S).");
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}
