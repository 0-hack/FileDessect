"use strict";

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const browseBtn = document.getElementById("browseBtn");
const statusEl = document.getElementById("status");
const reportEl = document.getElementById("report");
const capsEl = document.getElementById("capabilities");

// --- Capability badges ------------------------------------------------------
const CAP_LABELS = {
  file_type_detection: "File typing",
  pe_analysis: "PE / Windows RE",
  elf_analysis: "ELF / Linux RE",
  yara_signatures: "YARA",
  office_macros: "Office macros",
  virustotal_live: "VirusTotal live",
};

async function loadCapabilities() {
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    capsEl.innerHTML = "";
    for (const [key, label] of Object.entries(CAP_LABELS)) {
      const on = data.capabilities[key];
      const span = document.createElement("span");
      span.className = "cap " + (on ? "on" : "off");
      span.textContent = (on ? "● " : "○ ") + label;
      capsEl.appendChild(span);
    }
  } catch (e) {
    /* health is best-effort */
  }
}

// --- Upload handling --------------------------------------------------------
browseBtn.addEventListener("click", (e) => { e.stopPropagation(); fileInput.click(); });
dropzone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) analyze(fileInput.files[0]);
});

["dragenter", "dragover"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.add("drag");
  })
);
["dragleave", "drop"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag");
  })
);
dropzone.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) analyze(e.dataTransfer.files[0]);
});

async function analyze(file) {
  reportEl.classList.add("hidden");
  reportEl.innerHTML = "";
  statusEl.classList.remove("hidden");
  statusEl.innerHTML = `<div class="spinner"></div><div>Dissecting <strong>${escapeHtml(
    file.name
  )}</strong> (${humanSize(file.size)})…</div>`;

  const form = new FormData();
  form.append("file", file);

  try {
    const res = await fetch("/api/analyze", { method: "POST", body: form });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Analysis failed");
    }
    const report = await res.json();
    statusEl.classList.add("hidden");
    renderReport(report);
  } catch (e) {
    statusEl.classList.add("hidden");
    reportEl.classList.remove("hidden");
    reportEl.innerHTML = `<div class="error-box">⚠️ ${escapeHtml(e.message)}</div>`;
  }
}

// --- Rendering --------------------------------------------------------------
function renderReport(r) {
  const vt = findVtLink(r);
  const html = [];

  // Verdict banner
  html.push(`
    <div class="verdict verdict-${r.verdict}">
      <div class="verdict-head">
        <span class="verdict-badge">${r.verdict}</span>
        <span class="score">risk score: ${r.risk_score}</span>
      </div>
      <p class="verdict-explain">${escapeHtml(r.explanation)}</p>
    </div>
  `);

  // File metadata
  const id = r.identity || {};
  const h = id.hashes || {};
  html.push(`
    <div class="filemeta">
      <h3>File</h3>
      <dl class="kv">
        <dt>Name</dt><dd>${escapeHtml(r.filename)}</dd>
        <dt>Size</dt><dd>${humanSize(r.size)}</dd>
        <dt>Detected</dt><dd>${escapeHtml(id.magic || id.detected_kind || "unknown")}</dd>
        <dt>MIME</dt><dd>${escapeHtml(id.mime || "—")}</dd>
        <dt>SHA-256</dt><dd>${escapeHtml(h.sha256 || "—")}</dd>
        <dt>SHA-1</dt><dd>${escapeHtml(h.sha1 || "—")}</dd>
        <dt>MD5</dt><dd>${escapeHtml(h.md5 || "—")}</dd>
      </dl>
      ${vt ? `<a class="vt-link" href="${vt}" target="_blank" rel="noopener">↗ View reputation on VirusTotal</a>` : ""}
    </div>
  `);

  // Summary chips
  const s = r.summary || {};
  html.push(`<div class="summary-chips">${["critical", "high", "medium", "low", "info"]
    .map((sev) => {
      const n = s[sev] || 0;
      return `<span class="chip chip-${sev} ${n ? "has" : ""}">${n} ${sev}</span>`;
    })
    .join("")}</div>`);

  // Findings
  html.push('<div class="findings"><h3>Findings</h3>');
  if (!r.findings.length) {
    html.push('<p class="dz-note">No notable findings.</p>');
  }
  for (const f of r.findings) {
    html.push(renderFinding(f));
  }
  html.push("</div>");

  // Raw report
  html.push(`
    <div class="raw">
      <details>
        <summary><h3 style="display:inline">Raw report (JSON)</h3></summary>
        <pre>${escapeHtml(JSON.stringify(r, null, 2))}</pre>
      </details>
    </div>
  `);

  reportEl.innerHTML = html.join("");
  reportEl.classList.remove("hidden");
}

function renderFinding(f) {
  const sev = f.severity;
  let evidence = "";
  const data = f.data || {};
  if (Object.keys(data).length) {
    evidence = `<details class="evidence"><summary>Evidence</summary><pre>${escapeHtml(
      JSON.stringify(data, null, 2)
    )}</pre></details>`;
  }
  return `
    <div class="finding finding-${sev}">
      <div class="finding-head">
        <p class="finding-title">${escapeHtml(f.title)}</p>
        <span class="sev-tag sev-${sev}">${sev}</span>
      </div>
      <p class="finding-desc">${escapeHtml(f.description)}</p>
      <div class="finding-cat">category: ${escapeHtml(f.category)} · id: ${escapeHtml(f.id)}</div>
      ${evidence}
    </div>
  `;
}

function findVtLink(r) {
  for (const a of r.analyzers || []) {
    if (a.analyzer === "virustotal" && a.metadata && a.metadata.permalink) {
      return a.metadata.permalink;
    }
  }
  return null;
}

// --- Helpers ----------------------------------------------------------------
function humanSize(n) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let size = n;
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
  return (i === 0 ? size : size.toFixed(1)) + " " + units[i];
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

loadCapabilities();
