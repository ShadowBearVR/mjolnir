// Licensed under the Apache-2.0 license
// SPDX-License-Identifier: Apache-2.0

// TODO(security): Static client-only review SPA hosted on Google Cloud Storage.
// Reviewer LDAP handles are self-entered solely to namespace non-sensitive TP/FP
// card verdicts in browser localStorage before explicit JSON file download.
// No authentication credentials, session cookies, OAuth tokens, server-side
// state-changing endpoints (CSRF), or SQL databases are used by this application.

const STORAGE_PREFIX = "mjolnir_blind_v1";
const ACTIVE_LDAP_PREFIX = "mjolnir_blind_active_ldap";
const MAX_IMPORT_BYTES = 2 * 1024 * 1024;
const VALID_CARD_ID_RE = /^BF-\d{4}$/;
const SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational"];

const state = {
  deck: null,
  cards: [],
  filteredIndices: [],
  activeIndex: 0,
  filterMode: "all",
  searchQuery: "",
  reviewerLdap: "",
  reviews: {},
  activePocTab: "diff",
  sourceContextMode: "25",
  sourceLinesCache: new Map(),
};

function byId(id) {
  return document.getElementById(id);
}

function normalizeLdap(raw) {
  return String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/@.*$/, "")
    .replace(/[^a-z0-9._-]/g, "")
    .slice(0, 64);
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

function isPass2() {
  return Boolean(state.deck && state.deck.pass === "pass2");
}

function getCardEntry(reviewId) {
  const entry = state.reviews[reviewId];
  if (!entry || typeof entry !== "object") {
    return {
      verdict: "",
      expert_severity: "",
      poc_demonstrates: "",
      flagged: false,
      notes: "",
      updated_at: "",
    };
  }
  return entry;
}

function isCardCompleted(reviewId) {
  const entry = getCardEntry(reviewId);
  if (isPass2()) {
    return entry.poc_demonstrates === "yes" || entry.poc_demonstrates === "no";
  }
  return entry.verdict === "TP" || entry.verdict === "FP";
}

function storageKeyFor(deckId, ldap) {
  return `${STORAGE_PREFIX}:${deckId}:${ldap}`;
}

function activeLdapKeyFor(deckId) {
  return `${ACTIVE_LDAP_PREFIX}:${deckId}`;
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

function sanitizeStoredReviews(rawMap) {
  const cleaned = {};
  if (!rawMap || typeof rawMap !== "object") return cleaned;
  for (const [rid, val] of Object.entries(rawMap)) {
    if (!VALID_CARD_ID_RE.test(rid) || !val || typeof val !== "object") continue;
    const rawVerdict = String(val.verdict || "").toUpperCase();
    const verdict = rawVerdict === "TP" || rawVerdict === "FP" ? rawVerdict : "";
    const rawPoc = String(val.poc_demonstrates || val.verdict || "").toLowerCase();
    const pocDem = rawPoc === "yes" || rawPoc === "no" ? rawPoc : "";
    const sev = normalizeSeverity(val.expert_severity);
    const flagged = Boolean(val.flagged);
    const notes = String(val.notes || "").slice(0, 1000);
    const updatedAt = String(val.updated_at || "").slice(0, 40);
    if (verdict || pocDem || sev || flagged || notes) {
      cleaned[rid] = {
        verdict,
        expert_severity: sev,
        poc_demonstrates: pocDem,
        flagged,
        notes,
        updated_at: updatedAt,
      };
    }
  }
  return cleaned;
}

function saveReviewsToStorage() {
  const statusEl = byId("autosave-status-label");
  if (!state.deck || !state.reviewerLdap) {
    if (statusEl) statusEl.textContent = "Enter LDAP to autosave";
    return;
  }
  try {
    const payload = {
      schema_version: 1,
      deck_id: state.deck.deck_id,
      pass: state.deck.pass,
      reviewer_ldap: state.reviewerLdap,
      saved_at: new Date().toISOString(),
      reviews: state.reviews,
    };
    window.localStorage.setItem(
      storageKeyFor(state.deck.deck_id, state.reviewerLdap),
      JSON.stringify(payload)
    );
    window.localStorage.setItem(activeLdapKeyFor(state.deck.deck_id), state.reviewerLdap);
    if (statusEl) {
      statusEl.textContent = `Saved locally \u2022 ${formatClockTime(new Date())}`;
    }
  } catch (_err) {
    if (statusEl) statusEl.textContent = "Local save blocked";
    showNotice(
      "Browser localStorage write failed (storage disabled or quota full). Use Download Review JSON frequently to back up your work."
    );
  }
}

function loadReviewsForLdap(ldap) {
  if (!state.deck || !ldap) {
    state.reviews = {};
    return;
  }
  try {
    const raw = window.localStorage.getItem(storageKeyFor(state.deck.deck_id, ldap));
    if (!raw) {
      state.reviews = {};
      return;
    }
    const parsed = JSON.parse(raw);
    state.reviews = sanitizeStoredReviews(parsed && parsed.reviews);
  } catch (_err) {
    state.reviews = {};
  }
}

async function checkBrowserStoragePersistence() {
  try {
    if (navigator.storage && typeof navigator.storage.persist === "function") {
      await navigator.storage.persist();
    }
    if (navigator.storage && typeof navigator.storage.estimate === "function") {
      const est = await navigator.storage.estimate();
      if (est && typeof est.quota === "number" && est.quota > 0 && est.quota < 160 * 1024 * 1024) {
        showNotice(
          "Private / Incognito browsing detected (restricted storage quota). Closing all Incognito tabs will erase cached progress — switch to a regular browser window or click Download Review JSON before closing."
        );
      }
    }
  } catch (_err) {
    // Ignore unsupported storage persistence APIs.
  }
}

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

function cardMatchesFilter(card) {
  const entry = getCardEntry(card.review_id);
  if (state.filterMode === "unlabeled" && isCardCompleted(card.review_id)) return false;
  if (state.filterMode === "tp") {
    if (isPass2() ? entry.poc_demonstrates !== "yes" : entry.verdict !== "TP") return false;
  }
  if (state.filterMode === "fp") {
    if (isPass2() ? entry.poc_demonstrates !== "no" : entry.verdict !== "FP") return false;
  }
  if (state.filterMode === "flagged" && !entry.flagged) return false;

  if (state.searchQuery) {
    const q = state.searchQuery.toLowerCase();
    const hay = `${card.review_id} ${card.file} ${card.location || ""} ${card.cwe || ""} ${card.title || ""} ${card.description || ""}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function recomputeFilteredIndices(keepReviewId = "") {
  const indices = [];
  state.cards.forEach((card, idx) => {
    if (cardMatchesFilter(card)) indices.push(idx);
  });
  state.filteredIndices = indices;

  if (keepReviewId) {
    const exactIdx = state.cards.findIndex((c) => c.review_id === keepReviewId);
    if (exactIdx >= 0 && indices.includes(exactIdx)) {
      state.activeIndex = exactIdx;
      return;
    }
  }
  if (indices.length > 0 && !indices.includes(state.activeIndex)) {
    state.activeIndex = indices[0];
  }
}

function updateTopbarProgress() {
  const total = state.cards.length;
  let completed = 0;
  let tpCount = 0;
  let fpCount = 0;
  let flaggedCount = 0;

  for (const card of state.cards) {
    const e = getCardEntry(card.review_id);
    if (e.flagged) flaggedCount += 1;
    if (isPass2()) {
      if (e.poc_demonstrates === "yes") {
        completed += 1;
        tpCount += 1;
      } else if (e.poc_demonstrates === "no") {
        completed += 1;
        fpCount += 1;
      }
    } else {
      if (e.verdict === "TP") {
        completed += 1;
        tpCount += 1;
      } else if (e.verdict === "FP") {
        completed += 1;
        fpCount += 1;
      }
    }
  }

  const pct = total > 0 ? Math.min(100, Math.round((completed / total) * 1000) / 10) : 0;
  const rect = byId("progress-rect");
  if (rect) rect.setAttribute("width", String(pct));

  const labelEl = byId("progress-count-label");
  if (labelEl) {
    labelEl.textContent = `${completed} / ${total} (${Math.round(pct)}%)`;
  }

  const dlBtn = byId("btn-download-json");
  if (dlBtn) {
    const allDone = total > 0 && completed === total;
    dlBtn.classList.toggle("btn-complete", allDone);
    dlBtn.classList.toggle("btn-primary", !allDone);
    dlBtn.textContent = allDone
      ? `Download Review JSON (${completed}/${total} Complete)`
      : `Download Review JSON (${completed}/${total})`;
  }

  const tabAll = byId("filter-tab-all");
  const tabUnlabeled = byId("filter-tab-unlabeled");
  const tabTp = byId("filter-tab-tp");
  const tabFp = byId("filter-tab-fp");
  const tabFlag = byId("filter-tab-flagged");
  if (tabAll) tabAll.textContent = `All (${total})`;
  if (tabUnlabeled) tabUnlabeled.textContent = `Unlabeled (${total - completed})`;
  if (tabTp) tabTp.textContent = isPass2() ? `Yes (${tpCount})` : `TP (${tpCount})`;
  if (tabFp) tabFp.textContent = isPass2() ? `No (${fpCount})` : `FP (${fpCount})`;
  if (tabFlag) tabFlag.textContent = `Bookmarked (${flaggedCount})`;
}

function renderFileRail() {
  const listEl = byId("file-group-list");
  if (!listEl) return;
  listEl.replaceChildren();

  if (state.filteredIndices.length === 0) {
    const emptyDiv = document.createElement("div");
    emptyDiv.className = "save-status";
    emptyDiv.textContent = "No cards match the current filter.";
    listEl.appendChild(emptyDiv);
    return;
  }

  const fileGroups = new Map();
  for (const cardIdx of state.filteredIndices) {
    const card = state.cards[cardIdx];
    const fileKey = card.file || "unspecified";
    if (!fileGroups.has(fileKey)) {
      fileGroups.set(fileKey, []);
    }
    fileGroups.get(fileKey).push(cardIdx);
  }

  const activeCard = state.cards[state.activeIndex];
  const activeFile = activeCard ? activeCard.file : "";

  for (const [filePath, groupCardIndices] of fileGroups.entries()) {
    const doneInGroup = groupCardIndices.filter((idx) =>
      isCardCompleted(state.cards[idx].review_id)
    ).length;

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "file-group-btn";
    btn.setAttribute("role", "listitem");
    btn.setAttribute("title", filePath);
    if (filePath === activeFile) {
      btn.classList.add("active");
    }

    const nameSpan = document.createElement("span");
    nameSpan.className = "file-name-trunc";
    nameSpan.textContent = filePath;

    const countSpan = document.createElement("span");
    countSpan.className = "file-count-badge";
    if (doneInGroup === groupCardIndices.length) {
      countSpan.classList.add("done");
    }
    countSpan.textContent = `${doneInGroup}/${groupCardIndices.length}`;

    btn.appendChild(nameSpan);
    btn.appendChild(countSpan);

    btn.addEventListener("click", () => {
      const firstUnlabeled = groupCardIndices.find(
        (idx) => !isCardCompleted(state.cards[idx].review_id)
      );
      state.activeIndex = firstUnlabeled !== undefined ? firstUnlabeled : groupCardIndices[0];
      renderActiveCard();
      renderFileRail();
    });

    listEl.appendChild(btn);
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
  rangeEl.textContent = `Showing L${winStart}\u2013L${winEnd} of ${total} \u2022 Highlighted L${focusStart}\u2013L${focusEnd}`;

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
    if (firstHighlightEl) {
      const targetOffset = Math.max(0, firstHighlightEl.offsetTop - 90);
      scrollEl.scrollTop = targetOffset;
    } else {
      scrollEl.scrollTop = 0;
    }
  });
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

function renderActiveCard() {
  const shell = byId("active-card-shell");
  if (!shell) return;

  if (state.filteredIndices.length === 0 || !state.cards[state.activeIndex]) {
    byId("card-id-badge").textContent = "--";
    byId("card-title-heading").textContent = "No cards match the active filter.";
    byId("card-location-code").textContent = "Clear search or switch filter tab on the left.";
    byId("card-github-link").classList.add("hidden");
    byId("section-source-snippet").classList.add("hidden");
    byId("card-description-content").replaceChildren();
    byId("section-attack-vector").classList.add("hidden");
    byId("section-recommendation").classList.add("hidden");
    byId("section-pass2-poc").classList.add("hidden");
    return;
  }

  const card = state.cards[state.activeIndex];
  const entry = getCardEntry(card.review_id);
  const posInFiltered = state.filteredIndices.indexOf(state.activeIndex) + 1;

  byId("card-id-badge").textContent = card.review_id;

  const sevNorm = normalizeSeverity(card.reported_severity) || "Medium";
  const sevBadge = byId("card-sev-badge");
  sevBadge.className = `badge-sev badge-sev-${sevNorm}`;
  sevBadge.textContent = `Reported: ${sevNorm}`;

  const cwePill = byId("card-cwe-pill");
  cwePill.textContent = card.cwe || "Unclassified CWE";

  byId("card-position-pill").textContent = `Card ${posInFiltered} of ${state.filteredIndices.length}`;

  const verdictPill = byId("card-current-verdict-pill");
  if (isPass2()) {
    if (entry.poc_demonstrates === "yes") {
      verdictPill.textContent = "Graded: Yes (Demonstrates)";
    } else if (entry.poc_demonstrates === "no") {
      verdictPill.textContent = "Graded: No";
    } else {
      verdictPill.textContent = entry.flagged ? "Bookmarked (Unlabeled)" : "Unlabeled";
    }
  } else if (entry.verdict === "TP") {
    verdictPill.textContent = entry.expert_severity
      ? `Graded: TP (${entry.expert_severity})`
      : "Graded: TP";
  } else if (entry.verdict === "FP") {
    verdictPill.textContent = "Graded: FP";
  } else {
    verdictPill.textContent = entry.flagged ? "Bookmarked (Unlabeled)" : "Unlabeled";
  }

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
  if (isPass2()) {
    pocSec.classList.remove("hidden");
    renderPass2PocTabContent(card);
  } else {
    pocSec.classList.add("hidden");
  }

  byId("pass1-verdict-group").classList.toggle("hidden", isPass2());
  byId("pass1-severity-row").classList.toggle("hidden", isPass2());
  byId("pass2-verdict-group").classList.toggle("hidden", !isPass2());

  byId("grade-helper-text").textContent = isPass2()
    ? "Yes = The synthesized PoC test exercises the claimed root cause and fails/panics for that security violation without modifying production logic. No = Test fails for an unrelated setup/compile reason or tests a tautology."
    : "TP = Genuine security vulnerability under the repository threat model. FP = Not exploitable, prevented by existing checks/hardware invariants, or out of threat model scope.";

  byId("btn-verdict-tp").classList.toggle("active-tp", entry.verdict === "TP");
  byId("btn-verdict-fp").classList.toggle("active-fp", entry.verdict === "FP");
  byId("btn-verdict-yes").classList.toggle("active-tp", entry.poc_demonstrates === "yes");
  byId("btn-verdict-no").classList.toggle("active-fp", entry.poc_demonstrates === "no");

  const flagBtn = byId("btn-toggle-flag");
  flagBtn.classList.toggle("active-flag", Boolean(entry.flagged));

  for (const sev of SEVERITY_LEVELS) {
    const idSuffix = sev === "Informational" ? "info" : sev.toLowerCase();
    const sBtn = byId(`btn-sev-${idSuffix}`);
    if (sBtn) sBtn.classList.toggle("active", entry.expert_severity === sev);
  }

  const notesEl = byId("textarea-card-notes");
  if (notesEl && notesEl.value !== (entry.notes || "")) {
    notesEl.value = entry.notes || "";
  }

  byId("btn-prev-card").disabled = posInFiltered <= 1;
  byId("btn-next-card").disabled = posInFiltered >= state.filteredIndices.length;
}

function refreshAllViews(keepReviewId = "") {
  recomputeFilteredIndices(keepReviewId);
  updateTopbarProgress();
  renderFileRail();
  renderActiveCard();
}

function mutateCurrentEntry(mutator) {
  const card = state.cards[state.activeIndex];
  if (!card) return;
  if (!state.reviewerLdap) {
    openLdapModal();
    return;
  }
  const prev = getCardEntry(card.review_id);
  const next = {
    verdict: prev.verdict || "",
    expert_severity: prev.expert_severity || "",
    poc_demonstrates: prev.poc_demonstrates || "",
    flagged: Boolean(prev.flagged),
    notes: prev.notes || "",
    updated_at: new Date().toISOString(),
  };
  mutator(next, card);
  if (!next.verdict && !next.poc_demonstrates && !next.expert_severity && !next.flagged && !next.notes) {
    delete state.reviews[card.review_id];
  } else {
    state.reviews[card.review_id] = next;
  }
  saveReviewsToStorage();
  refreshAllViews(card.review_id);
}

function setPass1Verdict(verdict) {
  mutateCurrentEntry((entry, card) => {
    entry.verdict = verdict;
    if (verdict === "TP" && !entry.expert_severity) {
      entry.expert_severity = normalizeSeverity(card.reported_severity) || "Medium";
    }
    if (verdict === "FP") {
      entry.expert_severity = "";
    }
  });
}

function setPass2Verdict(yesNo) {
  mutateCurrentEntry((entry) => {
    entry.poc_demonstrates = yesNo;
  });
}

function setExpertSeverity(sev) {
  if (isPass2()) return;
  mutateCurrentEntry((entry) => {
    entry.expert_severity = entry.expert_severity === sev ? "" : sev;
  });
}

function toggleBookmark() {
  mutateCurrentEntry((entry) => {
    entry.flagged = !entry.flagged;
  });
}

function clearCurrentVerdict() {
  mutateCurrentEntry((entry) => {
    entry.verdict = "";
    entry.poc_demonstrates = "";
    entry.expert_severity = "";
  });
}

function stepCard(delta) {
  if (state.filteredIndices.length === 0) return;
  const pos = state.filteredIndices.indexOf(state.activeIndex);
  if (pos < 0) {
    state.activeIndex = state.filteredIndices[0];
  } else {
    const nextPos = Math.max(0, Math.min(state.filteredIndices.length - 1, pos + delta));
    state.activeIndex = state.filteredIndices[nextPos];
  }
  renderFileRail();
  renderActiveCard();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function jumpNextUnlabeled() {
  if (state.cards.length === 0) return;
  const n = state.cards.length;
  for (let offset = 1; offset <= n; offset += 1) {
    const idx = (state.activeIndex + offset) % n;
    if (!isCardCompleted(state.cards[idx].review_id)) {
      if (state.filterMode !== "all" && state.filterMode !== "unlabeled") {
        setFilterMode("all");
      }
      state.activeIndex = idx;
      refreshAllViews(state.cards[idx].review_id);
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
  }
  showNotice("All cards in this deck have been graded! Click Download Review JSON to export your file.", true);
}

function setFilterMode(mode) {
  state.filterMode = mode;
  for (const m of ["all", "unlabeled", "tp", "fp", "flagged"]) {
    const tab = byId(`filter-tab-${m}`);
    if (tab) tab.classList.toggle("active", m === mode);
  }
  refreshAllViews();
}

function openLdapModal() {
  const overlay = byId("ldap-modal-overlay");
  const input = byId("input-reviewer-ldap");
  const errEl = byId("ldap-form-error");
  if (errEl) errEl.textContent = "";
  if (input) input.value = state.reviewerLdap || "";
  if (overlay) overlay.classList.remove("hidden");
  if (input) input.focus();
}

function closeLdapModal() {
  const overlay = byId("ldap-modal-overlay");
  if (overlay) overlay.classList.add("hidden");
}

function applyReviewerLdap(rawInput) {
  const ldap = normalizeLdap(rawInput);
  const errEl = byId("ldap-form-error");
  if (!ldap || ldap.length < 2) {
    if (errEl) errEl.textContent = "Please enter a valid LDAP username (at least 2 characters).";
    return false;
  }
  state.reviewerLdap = ldap;
  byId("active-ldap-pill").textContent = `LDAP: ${ldap}`;
  loadReviewsForLdap(ldap);
  saveReviewsToStorage();
  closeLdapModal();
  checkBrowserStoragePersistence();

  const firstUnlabeledIdx = state.cards.findIndex((c) => !isCardCompleted(c.review_id));
  if (firstUnlabeledIdx >= 0) {
    state.activeIndex = firstUnlabeledIdx;
  }
  refreshAllViews();
  return true;
}

function downloadReviewJson() {
  if (!state.deck) return;
  if (!state.reviewerLdap) {
    openLdapModal();
    return;
  }

  let completedCount = 0;
  for (const card of state.cards) {
    if (isCardCompleted(card.review_id)) completedCount += 1;
  }

  const exportPayload = {
    schema_version: 1,
    deck_id: state.deck.deck_id,
    pass: state.deck.pass,
    project_name: state.deck.project_name || "",
    repo_name: state.deck.repo_name || "",
    pinned_rev: state.deck.pinned_rev || "",
    reviewer_ldap: state.reviewerLdap,
    exported_at: new Date().toISOString(),
    completed_count: completedCount,
    total_count: state.cards.length,
    reviews: state.reviews,
  };

  const jsonBytes = JSON.stringify(exportPayload, null, 2);
  const blob = new Blob([jsonBytes], { type: "application/json" });
  const blobUrl = URL.createObjectURL(blob);
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const filename = `mjolnir-${state.deck.pass}-${state.reviewerLdap}-${ts}.json`;

  const anchor = document.createElement("a");
  anchor.setAttribute("href", blobUrl);
  anchor.setAttribute("download", filename);
  anchor.className = "hidden";
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1500);

  showNotice(
    `Downloaded ${filename} (${completedCount}/${state.cards.length} cards graded). Send this JSON file to the study coordinator when finished.`,
    true
  );
}

async function handleImportJsonFile(file) {
  if (!file || !state.deck) return;
  if (!file.name.toLowerCase().endsWith(".json")) {
    showNotice("Import rejected: please select a .json review export file.");
    return;
  }
  if (file.size > MAX_IMPORT_BYTES) {
    showNotice("Import rejected: JSON file exceeds the 2 MiB safety limit.");
    return;
  }
  try {
    const rawText = await file.text();
    const parsed = JSON.parse(rawText);
    if (!parsed || typeof parsed !== "object" || typeof parsed.reviews !== "object") {
      showNotice("Import rejected: invalid review JSON structure (missing 'reviews' map).");
      return;
    }
    const importedLdap = normalizeLdap(parsed.reviewer_ldap);
    if (importedLdap && !state.reviewerLdap) {
      state.reviewerLdap = importedLdap;
      byId("active-ldap-pill").textContent = `LDAP: ${importedLdap}`;
      closeLdapModal();
    }
    const cleaned = sanitizeStoredReviews(parsed.reviews);
    const validDeckIds = new Set(state.cards.map((c) => c.review_id));
    let mergedCount = 0;
    for (const [rid, entry] of Object.entries(cleaned)) {
      if (validDeckIds.has(rid)) {
        state.reviews[rid] = entry;
        mergedCount += 1;
      }
    }
    saveReviewsToStorage();
    refreshAllViews();
    showNotice(`Restored ${mergedCount} card review(s) from ${file.name}.`, true);
  } catch (_err) {
    showNotice("Import failed: file could not be parsed as valid JSON.");
  }
}

function wireEvents() {
  byId("btn-dismiss-notice").addEventListener("click", hideNotice);
  byId("btn-switch-ldap").addEventListener("click", openLdapModal);

  byId("form-ldap-entry").addEventListener("submit", (e) => {
    e.preventDefault();
    applyReviewerLdap(byId("input-reviewer-ldap").value);
  });

  const toggleTm = () => {
    const drawer = byId("threat-model-drawer");
    const btn = byId("btn-toggle-tm");
    const isNowHidden = drawer.classList.toggle("hidden");
    btn.setAttribute("aria-expanded", String(!isNowHidden));
  };
  byId("btn-toggle-tm").addEventListener("click", toggleTm);
  byId("btn-close-tm").addEventListener("click", () => {
    byId("threat-model-drawer").classList.add("hidden");
    byId("btn-toggle-tm").setAttribute("aria-expanded", "false");
  });

  byId("btn-download-json").addEventListener("click", downloadReviewJson);
  byId("btn-load-json").addEventListener("click", () => {
    byId("input-load-json").click();
  });
  byId("input-load-json").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) handleImportJsonFile(file);
    e.target.value = "";
  });

  for (const mode of ["all", "unlabeled", "tp", "fp", "flagged"]) {
    byId(`filter-tab-${mode}`).addEventListener("click", () => setFilterMode(mode));
  }

  byId("input-search-cards").addEventListener("input", (e) => {
    state.searchQuery = String(e.target.value || "").trim();
    refreshAllViews();
  });

  byId("btn-verdict-tp").addEventListener("click", () => setPass1Verdict("TP"));
  byId("btn-verdict-fp").addEventListener("click", () => setPass1Verdict("FP"));
  byId("btn-verdict-yes").addEventListener("click", () => setPass2Verdict("yes"));
  byId("btn-verdict-no").addEventListener("click", () => setPass2Verdict("no"));
  byId("btn-toggle-flag").addEventListener("click", toggleBookmark);
  byId("btn-clear-verdict").addEventListener("click", clearCurrentVerdict);

  for (const sev of SEVERITY_LEVELS) {
    const idSuffix = sev === "Informational" ? "info" : sev.toLowerCase();
    byId(`btn-sev-${idSuffix}`).addEventListener("click", () => setExpertSeverity(sev));
  }

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

  let notesTimer = null;
  byId("textarea-card-notes").addEventListener("input", (e) => {
    const val = String(e.target.value || "").slice(0, 1000);
    window.clearTimeout(notesTimer);
    notesTimer = window.setTimeout(() => {
      mutateCurrentEntry((entry) => {
        entry.notes = val;
      });
    }, 220);
  });

  byId("btn-prev-card").addEventListener("click", () => stepCard(-1));
  byId("btn-next-card").addEventListener("click", () => stepCard(1));
  byId("btn-next-unlabeled").addEventListener("click", jumpNextUnlabeled);

  window.addEventListener("keydown", (e) => {
    const modalOpen = !byId("ldap-modal-overlay").classList.contains("hidden");
    if (modalOpen) return;

    const tag = document.activeElement ? document.activeElement.tagName : "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") {
      if (e.key === "Escape") {
        document.activeElement.blur();
      }
      return;
    }
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    const k = e.key;
    if (k === "/") {
      e.preventDefault();
      byId("input-search-cards").focus();
    } else if (k === "j" || k === "ArrowRight") {
      e.preventDefault();
      stepCard(1);
    } else if (k === "k" || k === "ArrowLeft") {
      e.preventDefault();
      stepCard(-1);
    } else if (!isPass2() && (k === "t" || k === "T")) {
      e.preventDefault();
      setPass1Verdict("TP");
    } else if (!isPass2() && (k === "f" || k === "F")) {
      e.preventDefault();
      setPass1Verdict("FP");
    } else if (isPass2() && (k === "y" || k === "Y")) {
      e.preventDefault();
      setPass2Verdict("yes");
    } else if (isPass2() && (k === "n" || k === "N")) {
      e.preventDefault();
      setPass2Verdict("no");
    } else if (k === "b" || k === "B") {
      e.preventDefault();
      toggleBookmark();
    } else if (!isPass2() && ["1", "2", "3", "4", "5"].includes(k)) {
      e.preventDefault();
      setExpertSeverity(SEVERITY_LEVELS[Number(k) - 1]);
    }
  });
}

async function initApp() {
  wireEvents();
  try {
    const res = await fetch("./deck.json", { cache: "no-store" });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const deck = await res.json();
    if (!deck || !Array.isArray(deck.cards)) {
      throw new Error("Malformed deck.json payload");
    }
    state.deck = deck;
    state.cards = deck.cards;

    const passLabel = deck.pass === "pass2" ? "Pass 2: PoC Audit" : "Pass 1: Blind Claim Review";
    byId("deck-title").textContent = `Mjolnir Blind Review \u2014 ${deck.repo_name || "Target"} (${passLabel})`;
    const shortRev = deck.pinned_rev ? String(deck.pinned_rev).slice(0, 12) : "pinned";
    byId("target-commit-pill").textContent = `${deck.repo_name || "repo"} @ ${shortRev}`;

    const treeLink = byId("repo-tree-link");
    if (typeof deck.repo_tree_url === "string" && deck.repo_tree_url.startsWith("https://github.com/")) {
      treeLink.setAttribute("href", deck.repo_tree_url);
      treeLink.classList.remove("hidden");
    }

    byId("threat-model-content").textContent =
      deck.threat_model_markdown || "No repository threat model markdown attached to this deck.";

    let savedLdap = "";
    try {
      savedLdap = normalizeLdap(window.localStorage.getItem(activeLdapKeyFor(deck.deck_id)));
    } catch (_err) {
      savedLdap = "";
    }

    if (savedLdap) {
      applyReviewerLdap(savedLdap);
    } else {
      refreshAllViews();
      openLdapModal();
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
