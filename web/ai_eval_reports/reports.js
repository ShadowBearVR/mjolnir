// Licensed under the Apache-2.0 license
// SPDX-License-Identifier: Apache-2.0

// TODO(security): Read-only static report viewer served from Google Cloud Storage.
// All Markdown documents are rendered strictly via safe DOM APIs (createElement /
// createTextNode) with zero innerHTML, session cookies, credentials, or SQL queries.

const DOC_PATHS = {
  v2_report: "./docs/v2_report.md",
  v2_scorecard: "./docs/v2_scorecard.md",
  v2_meta: "./docs/v2_meta_reviews.md",
  v1_report: "./docs/v1_report.md",
  v1_scorecard: "./docs/v1_scorecard.md",
};

const docCache = new Map();

function appendInlineRuns(parentEl, text) {
  const tokenRe = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]]+\]\(https:\/\/github\.com\/[^)\s]+\))/g;
  let cursor = 0;
  let match;
  while ((match = tokenRe.exec(text)) !== null) {
    if (match.index > cursor) {
      parentEl.appendChild(document.createTextNode(text.slice(cursor, match.index)));
    }
    const tok = match[0];
    if (tok.startsWith("`") && tok.endsWith("`")) {
      const c = document.createElement("code");
      c.className = "inline-code";
      c.textContent = tok.slice(1, -1);
      parentEl.appendChild(c);
    } else if (tok.startsWith("**") && tok.endsWith("**")) {
      const s = document.createElement("strong");
      s.textContent = tok.slice(2, -2);
      parentEl.appendChild(s);
    } else if (tok.startsWith("[")) {
      const m = tok.match(/^\[([^\]]+)\]\((https:\/\/github\.com\/[^)\s]+)\)$/);
      if (m) {
        const a = document.createElement("a");
        a.setAttribute("href", m[2]);
        a.setAttribute("target", "_blank");
        a.setAttribute("rel", "noopener noreferrer");
        a.textContent = m[1];
        parentEl.appendChild(a);
      } else {
        parentEl.appendChild(document.createTextNode(tok));
      }
    }
    cursor = tokenRe.lastIndex;
  }
  if (cursor < text.length) {
    parentEl.appendChild(document.createTextNode(text.slice(cursor)));
  }
}

function splitTableRow(line) {
  let trimmed = line.trim();
  if (trimmed.startsWith("|")) trimmed = trimmed.slice(1);
  if (trimmed.endsWith("|")) trimmed = trimmed.slice(0, -1);
  return trimmed.split("|").map((c) => c.trim());
}

function isTableDivider(line) {
  return /^\|?\s*:?-{2,}:?(\s*\|\s*:?-{2,}:?)+\s*\|?$/.test(line.trim());
}

function renderMarkdownDocument(mount, mdText) {
  mount.replaceChildren();
  const lines = String(mdText || "").split(/\r?\n/);
  const frag = document.createDocumentFragment();
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed) {
      i += 1;
      continue;
    }

    if (trimmed.startsWith("```")) {
      const codeLines = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) i += 1;
      const pre = document.createElement("pre");
      pre.className = "code-block";
      const code = document.createElement("code");
      code.textContent = codeLines.join("\n");
      pre.appendChild(code);
      frag.appendChild(pre);
      continue;
    }

    if (/^-{3,}$/.test(trimmed)) {
      frag.appendChild(document.createElement("hr"));
      i += 1;
      continue;
    }

    const headingMatch = trimmed.match(/^(#{1,4})\s+(.*)$/);
    if (headingMatch) {
      const level = Math.min(4, Math.max(2, headingMatch[1].length + (headingMatch[1].length === 1 ? 1 : 0)));
      const hEl = document.createElement(`h${level}`);
      appendInlineRuns(hEl, headingMatch[2]);
      frag.appendChild(hEl);
      i += 1;
      continue;
    }

    if (
      trimmed.includes("|") &&
      i + 1 < lines.length &&
      isTableDivider(lines[i + 1])
    ) {
      const headers = splitTableRow(lines[i]);
      i += 2;
      const wrap = document.createElement("div");
      wrap.className = "table-wrap";
      const table = document.createElement("table");
      table.className = "md-table";
      const thead = document.createElement("thead");
      const trHead = document.createElement("tr");
      for (const hCell of headers) {
        const th = document.createElement("th");
        appendInlineRuns(th, hCell);
        trHead.appendChild(th);
      }
      thead.appendChild(trHead);
      table.appendChild(thead);

      const tbody = document.createElement("tbody");
      while (i < lines.length && lines[i].trim().includes("|") && lines[i].trim() !== "") {
        const cells = splitTableRow(lines[i]);
        const tr = document.createElement("tr");
        for (const cVal of cells) {
          const td = document.createElement("td");
          appendInlineRuns(td, cVal);
          tr.appendChild(td);
        }
        tbody.appendChild(tr);
        i += 1;
      }
      table.appendChild(tbody);
      wrap.appendChild(table);
      frag.appendChild(wrap);
      continue;
    }

    if (trimmed.startsWith(">")) {
      const bq = document.createElement("blockquote");
      const qLines = [];
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        qLines.push(lines[i].trim().replace(/^>\s?/, ""));
        i += 1;
      }
      appendInlineRuns(bq, qLines.join(" "));
      frag.appendChild(bq);
      continue;
    }

    if (/^[-*]\s+/.test(trimmed)) {
      const ul = document.createElement("ul");
      while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) {
        const li = document.createElement("li");
        appendInlineRuns(li, lines[i].trim().replace(/^[-*]\s+/, ""));
        ul.appendChild(li);
        i += 1;
      }
      frag.appendChild(ul);
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      const ol = document.createElement("ol");
      while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
        const li = document.createElement("li");
        appendInlineRuns(li, lines[i].trim().replace(/^\d+\.\s+/, ""));
        ol.appendChild(li);
        i += 1;
      }
      frag.appendChild(ol);
      continue;
    }

    const pLines = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].trim().startsWith("#") &&
      !lines[i].trim().startsWith("```") &&
      !lines[i].trim().startsWith(">") &&
      !/^[-*]\s+/.test(lines[i].trim()) &&
      !/^\d+\.\s+/.test(lines[i].trim()) &&
      !/^-{3,}$/.test(lines[i].trim())
    ) {
      pLines.push(lines[i].trim());
      i += 1;
    }
    if (pLines.length > 0) {
      const p = document.createElement("p");
      appendInlineRuns(p, pLines.join(" "));
      frag.appendChild(p);
    } else {
      i += 1;
    }
  }

  mount.appendChild(frag);
}

async function selectDoc(docKey) {
  const path = DOC_PATHS[docKey] || DOC_PATHS.v2_report;
  const figSec = document.getElementById("v2-figures-section");
  if (figSec) {
    figSec.classList.toggle("hidden", docKey !== "v2_report" && docKey !== "v2_scorecard");
  }

  for (const btn of document.querySelectorAll(".tab-btn")) {
    btn.classList.toggle("active", btn.getAttribute("data-doc") === docKey);
  }

  const mount = document.getElementById("report-markdown-mount");
  if (!mount) return;

  if (docCache.has(path)) {
    renderMarkdownDocument(mount, docCache.get(path));
    return;
  }

  mount.textContent = "Loading document...";
  try {
    const res = await fetch(path, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    docCache.set(path, text);
    renderMarkdownDocument(mount, text);
  } catch (_err) {
    mount.textContent = `Could not load ${path}.`;
  }
}

function initReports() {
  for (const btn of document.querySelectorAll(".tab-btn")) {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-doc") || "v2_report";
      selectDoc(key);
    });
  }
  selectDoc("v2_report");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initReports);
} else {
  initReports();
}
