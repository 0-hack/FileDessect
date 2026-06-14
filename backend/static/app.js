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
  macho_analysis: "macOS Mach-O",
  script_analysis: "Scripts / code",
  disassembly: "Disassembly",
  rizin_engine: "Rizin engine",
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
  const vt = document.getElementById("vtToggle");
  form.append("virustotal", vt && vt.checked ? "true" : "false");

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
let lastReport = null;

function renderReport(r) {
  lastReport = r;
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

  // Export toolbar
  html.push(`
    <div class="toolbar">
      <button class="btn" data-export="markdown">⬇ Download report (Markdown)</button>
      <button class="btn" data-export="json">⬇ Download report (JSON)</button>
      <button class="btn" data-export="copy">⧉ Copy Markdown for expert review</button>
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

  // Full identified data + score breakdown
  html.push(renderDetails(r));
  html.push(renderScoring(r));

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

  // Wire up export buttons.
  reportEl.querySelectorAll("[data-export]").forEach((btn) => {
    btn.addEventListener("click", () => handleExport(btn.dataset.export));
  });
}

// --- Report export ----------------------------------------------------------
function handleExport(kind) {
  if (!lastReport) return;
  const shortHash = (lastReport.identity?.hashes?.sha256 || "report").slice(0, 12);
  if (kind === "json") {
    downloadBlob(JSON.stringify(lastReport, null, 2), `filedessect_${shortHash}.json`, "application/json");
  } else if (kind === "markdown") {
    downloadBlob(reportToMarkdown(lastReport), `filedessect_${shortHash}.md`, "text/markdown");
  } else if (kind === "copy") {
    const md = reportToMarkdown(lastReport);
    navigator.clipboard.writeText(md).then(
      () => flashCopied(),
      () => downloadBlob(md, `filedessect_${shortHash}.md`, "text/markdown")
    );
  }
}

function flashCopied() {
  const btn = reportEl.querySelector('[data-export="copy"]');
  if (!btn) return;
  const orig = btn.textContent;
  btn.textContent = "✓ Copied — paste to your expert";
  setTimeout(() => (btn.textContent = orig), 2500);
}

function downloadBlob(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function reportToMarkdown(r) {
  const L = [];
  const id = r.identity || {};
  const h = id.hashes || {};
  L.push(`# FileDessect analysis report`);
  L.push("");
  L.push(`> Generated by FileDessect for expert review. Static analysis only — the sample was never executed.`);
  L.push("");
  L.push(`## Verdict: ${String(r.verdict).toUpperCase()} (risk score ${r.risk_score})`);
  L.push("");
  L.push(r.explanation || "");
  if (r.scoring?.reason) L.push("", `**Scoring rationale:** ${r.scoring.reason}`);
  L.push("");
  L.push(`## File`);
  L.push("");
  L.push(`| Field | Value |`);
  L.push(`| --- | --- |`);
  L.push(`| Name | ${mdEsc(r.filename)} |`);
  L.push(`| Size | ${r.size} bytes |`);
  L.push(`| Detected type | ${mdEsc(id.magic || id.detected_kind || "unknown")} |`);
  L.push(`| MIME | ${mdEsc(id.mime || "—")} |`);
  L.push(`| SHA-256 | \`${h.sha256 || "—"}\` |`);
  L.push(`| SHA-1 | \`${h.sha1 || "—"}\` |`);
  L.push(`| MD5 | \`${h.md5 || "—"}\` |`);
  L.push(`| VirusTotal scan | ${r.virustotal_enabled === false ? "disabled by user" : "enabled"} |`);
  L.push(`| Analyzed at | ${r.analyzed_at || ""} |`);
  L.push("");

  // Findings
  L.push(`## Findings (${(r.findings || []).length})`);
  L.push("");
  if (!(r.findings || []).length) L.push("_No notable findings._", "");
  for (const f of r.findings || []) {
    L.push(`### [${f.severity.toUpperCase()}] ${mdEsc(f.title)}`);
    L.push(`- **Category:** ${f.category} · **ID:** \`${f.id}\``);
    L.push(`- ${mdEsc(f.description)}`);
    if (f.data && Object.keys(f.data).length) {
      L.push("- **Evidence:**");
      L.push("```json");
      L.push(JSON.stringify(f.data, null, 2));
      L.push("```");
    }
    L.push("");
  }

  // Score breakdown
  if (r.scoring?.breakdown?.length) {
    L.push(`## Score breakdown`);
    L.push("");
    L.push(`| Severity | Weight | Finding | Category |`);
    L.push(`| --- | --- | --- | --- |`);
    for (const b of r.scoring.breakdown)
      L.push(`| ${b.severity} | +${b.weight} | ${mdEsc(b.title)} | ${b.category} |`);
    L.push(`| **Total** | **${r.scoring.score}** | | |`);
    L.push("");
  }

  // Disassembly (assembly view) — valuable for an RE expert.
  const da = (r.analyzers || []).find((a) => a.analyzer === "disasm");
  if (da?.metadata?.disassembly?.length) {
    const m = da.metadata;
    L.push(`## Disassembly (entry point — ${m.engine}, ${m.architecture}, entry ${m.entry_point})`);
    if (m.signature_hits && Object.keys(m.signature_hits).length)
      L.push("", `Opcode signature hits: \`${JSON.stringify(m.signature_hits)}\``);
    L.push("", "```asm");
    for (const i of m.disassembly) {
      const note = i.note ? `  ; <== ${i.note}` : "";
      L.push(`${(i.addr + "").padEnd(12)}${(i.bytes || "").padEnd(18)}${i.mnemonic} ${i.op_str}${note}`);
    }
    L.push("```", "");
  }

  // Raw analyzer metadata appendix for completeness.
  L.push(`## Appendix: full analyzer metadata`);
  L.push("", "```json");
  L.push(JSON.stringify((r.analyzers || []).map((a) => ({ analyzer: a.analyzer, metadata: a.metadata, error: a.error })), null, 2));
  L.push("```", "");
  return L.join("\n");
}

function mdEsc(s) {
  return String(s == null ? "" : s).replace(/\|/g, "\\|").replace(/\n/g, " ");
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

// --- Score breakdown --------------------------------------------------------
function renderScoring(r) {
  const sc = r.scoring;
  if (!sc) return "";
  const rows = sc.breakdown
    .map(
      (b) => `
      <tr>
        <td><span class="sev-tag sev-${b.severity}">${b.severity}</span></td>
        <td class="num">+${b.weight}</td>
        <td>${escapeHtml(b.title)}</td>
        <td class="muted">${escapeHtml(b.category)}</td>
      </tr>`
    )
    .join("");
  const body = rows ||
    '<tr><td colspan="4" class="muted">No findings contributed to the score.</td></tr>';
  return `
    <div class="panel">
      <h3>How this score was calculated</h3>
      <p class="finding-desc">${escapeHtml(sc.reason)}</p>
      <table class="dtable">
        <thead><tr><th>Severity</th><th>Weight</th><th>Finding</th><th>Category</th></tr></thead>
        <tbody>${body}</tbody>
        <tfoot><tr>
          <td class="muted">Total</td>
          <td class="num"><strong>${sc.score}</strong></td>
          <td colspan="2" class="muted">Thresholds: suspicious ≥ ${sc.thresholds.suspicious}, malicious ≥ ${sc.thresholds.malicious}</td>
        </tr></tfoot>
      </table>
      <a class="vt-link" href="/scoring" target="_blank" rel="noopener">↗ How scoring &amp; verdicts work — full reference</a>
    </div>
  `;
}

// --- Full identified-data rendering ----------------------------------------
function renderDetails(r) {
  const by = {};
  for (const a of r.analyzers || []) by[a.analyzer] = a;
  const blocks = [];

  // Content & indicators
  const c = by.content && by.content.metadata;
  if (c) {
    const sub = [];
    sub.push(
      kvTable({
        "Entropy (0–8)": c.entropy,
        "Printable strings": c.string_count,
        "URLs": c.url_count,
        "IP addresses": c.ip_count,
        "Domains": c.domain_count,
        "Base64 blobs": c.base64_blob_count,
      })
    );
    if ((c.urls || []).length) sub.push(listBlock(`URLs (${c.urls.length})`, c.urls));
    if ((c.ips || []).length) sub.push(listBlock(`IP addresses (${c.ips.length})`, c.ips));
    if ((c.domains || []).length) sub.push(listBlock(`Domains (${c.domains.length})`, c.domains));
    if ((c.base64_blobs || []).length)
      sub.push(objTable(`Base64 blobs (${c.base64_blobs.length})`, c.base64_blobs, ["offset", "length", "preview"]));
    if ((c.readable_strings || []).length)
      sub.push(listBlock(`Human-readable strings (${c.readable_string_count})`, c.readable_strings, false));
    blocks.push(subpanel("Content & indicators", sub.join("")));
  }

  // PE
  const pe = by.pe && by.pe.metadata;
  if (pe && Object.keys(pe).length) {
    const sub = [];
    sub.push(
      kvTable({
        Type: pe.type,
        Architecture: pe.machine,
        "Compile time": pe.compile_time,
        "Digitally signed": fmtBool(pe.digitally_signed),
        "TLS callbacks": fmtBool(pe.tls_callbacks),
        "Imported functions": pe.import_count,
      })
    );
    if ((pe.capabilities || []).length) sub.push(capTable(pe.capabilities));
    if ((pe.sections || []).length)
      sub.push(
        objTable(`Sections (${pe.sections.length})`, pe.sections, [
          "name", "virtual_size", "raw_size", "entropy", "writable", "executable",
        ])
      );
    if (pe.imports) sub.push(importsBlock(pe.imports));
    blocks.push(subpanel("Windows PE (reverse engineering)", sub.join("")));
  }

  // ELF
  const elf = by.elf && by.elf.metadata;
  if (elf && Object.keys(elf).length) {
    const sub = [];
    sub.push(
      kvTable({
        Type: elf.type,
        Architecture: elf.arch,
        Bits: elf.bits,
        "Entry point": elf.entry_point,
        Stripped: fmtBool(elf.stripped),
        "Statically linked": fmtBool(elf.statically_linked),
        "Total symbols": elf.symbol_count,
      })
    );
    if ((elf.capabilities || []).length) sub.push(capTable(elf.capabilities));
    if ((elf.imported_symbols || []).length)
      sub.push(listBlock(`Imported symbols (${elf.imported_symbols.length})`, elf.imported_symbols));
    blocks.push(subpanel("Linux ELF (reverse engineering)", sub.join("")));
  }

  // Disassembly (assembly-level)
  const da = by.disasm && by.disasm.metadata;
  if (da && (da.disassembly || []).length) {
    blocks.push(subpanel(`Disassembly — assembly view (${da.engine || "capstone"})`, renderDisasm(da)));
  }

  // macOS Mach-O
  const mo = by.macho && by.macho.metadata;
  if (mo && mo.is_macho) {
    const sub = [
      kvTable({
        "File type": mo.filetype,
        Architecture: mo.arch,
        Bits: mo.bits,
        Universal: fmtBool(mo.fat),
        "Code signature": fmtBool(mo.code_signature),
        Encrypted: fmtBool(mo.encrypted),
        "Writable+executable segment": fmtBool(mo.rwx_segment),
      }),
    ];
    if ((mo.dylibs || []).length)
      sub.push(listBlock(`Linked libraries (${mo.dylib_count})`, mo.dylibs));
    blocks.push(subpanel("macOS Mach-O (reverse engineering)", sub.join("")));
  }

  // Script / source code
  const code = by.code && by.code.metadata;
  if (code && code.language) {
    const sub = [
      kvTable({
        Language: code.language,
        Lines: code.line_count,
        "launchd persistence": code.plist_persistence === undefined ? undefined : fmtBool(code.plist_persistence),
      }),
    ];
    if ((code.indicators || []).length)
      sub.push(
        objTable(`Detected constructs (${code.indicators.length})`, code.indicators, [
          "severity", "pattern", "why", "line",
        ])
      );
    blocks.push(subpanel(`Source code analysis (${code.language})`, sub.join("")));
  }

  // Office macros
  const off = by.office && by.office.metadata;
  if (off && off.has_macros) {
    const sub = [kvTable({ "Has macros": "yes", "Macro indicators": off.macro_indicators })];
    blocks.push(subpanel("Office document macros", sub.join("")));
  }

  // YARA
  const y = by.yara && by.yara.metadata;
  if (y && (y.matched_rules || []).length) {
    blocks.push(subpanel("YARA matches", listBlock(`Matched rules (${y.matched_rules.length})`, y.matched_rules)));
  }

  // VirusTotal
  const vt = by.virustotal && by.virustotal.metadata;
  if (vt) {
    const kv = { Queried: fmtBool(vt.queried), Known: vt.known === undefined ? "—" : fmtBool(vt.known) };
    if (vt.stats) {
      kv.Malicious = vt.stats.malicious;
      kv.Suspicious = vt.stats.suspicious;
      kv.Harmless = vt.stats.harmless;
      kv.Undetected = vt.stats.undetected;
    }
    let block = kvTable(kv);
    if ((vt.names || []).length) block += listBlock("Known filenames", vt.names);
    if (vt.permalink) block += `<a class="vt-link" href="${vt.permalink}" target="_blank" rel="noopener">↗ Open VirusTotal report</a>`;
    blocks.push(subpanel("VirusTotal reputation", block));
  }

  if (!blocks.length) return "";
  return `<div class="findings"><h3>Identified data (full detail)</h3>${blocks.join("")}</div>`;
}

// --- Detail render helpers --------------------------------------------------
function subpanel(title, inner) {
  return `<details class="subpanel" open><summary>${escapeHtml(title)}</summary><div class="subpanel-body">${inner}</div></details>`;
}

function kvTable(obj) {
  const rows = Object.entries(obj)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `<tr><td class="muted">${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`)
    .join("");
  return `<table class="dtable kvt"><tbody>${rows}</tbody></table>`;
}

function listBlock(title, arr, open = true) {
  const items = arr.map((v) => `<li>${escapeHtml(v)}</li>`).join("");
  return `<details class="evidence"${open ? " open" : ""}><summary>${escapeHtml(title)}</summary><ul class="datalist">${items}</ul></details>`;
}

function objTable(title, arr, cols) {
  const head = cols.map((c) => `<th>${escapeHtml(c.replace(/_/g, " "))}</th>`).join("");
  const rows = arr
    .map((o) => `<tr>${cols.map((c) => `<td>${escapeHtml(fmtCell(o[c]))}</td>`).join("")}</tr>`)
    .join("");
  return `<details class="evidence" open><summary>${escapeHtml(title)}</summary><table class="dtable"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></details>`;
}

function capTable(caps) {
  const rows = caps
    .map((c) => `<tr><td><span class="sev-tag sev-${c.severity}">${c.severity}</span></td><td>${escapeHtml(c.capability)}</td></tr>`)
    .join("");
  return `<details class="evidence" open><summary>Capabilities (${caps.length})</summary><table class="dtable"><tbody>${rows}</tbody></table></details>`;
}

function importsBlock(imports) {
  const dlls = Object.entries(imports);
  if (!dlls.length) return "";
  const inner = dlls
    .map(([dll, fns]) => `<details class="evidence"><summary>${escapeHtml(dll)} (${fns.length})</summary><ul class="datalist">${fns.map((f) => `<li>${escapeHtml(f)}</li>`).join("")}</ul></details>`)
    .join("");
  return `<details class="evidence" open><summary>Imported functions by DLL (${dlls.length})</summary>${inner}</details>`;
}

function renderDisasm(da) {
  const meta = kvTable({
    Engine: da.engine,
    Architecture: da.architecture,
    "Entry point": da.entry_point,
    "Instructions shown": da.instructions_shown,
    "Rizin functions": da.rizin_function_count,
  });
  const lines = da.disassembly
    .map((i) => {
      const cls = i.flag ? ` class="asm-flag asm-${i.flag}"` : "";
      const note = i.note ? `  ; ⚠ ${escapeHtml(i.note)}` : "";
      const addr = escapeHtml(i.addr.padEnd(12));
      const bytes = escapeHtml((i.bytes || "").padEnd(18).slice(0, 18));
      const ins = escapeHtml(`${i.mnemonic} ${i.op_str}`.trim());
      return `<div${cls}>${addr}${bytes}${ins}${note}</div>`;
    })
    .join("");
  const legend =
    '<p class="dz-note">Highlighted lines are suspicious machine-code constructs ' +
    '(PEB access, direct syscalls, anti-analysis, anti-debug, stack pivots). ' +
    'For deep interactive debugging, open the file in <strong>Cutter</strong> ' +
    '(<a class="vt-link" href="https://cutter.re" target="_blank" rel="noopener">cutter.re</a>), ' +
    'which uses the same Rizin/Capstone engine.</p>';
  return `${meta}${legend}<pre class="asm">${lines}</pre>`;
}

function fmtBool(v) {
  if (v === true) return "yes";
  if (v === false) return "no";
  return v;
}
function fmtCell(v) {
  if (v === true) return "✓";
  if (v === false) return "—";
  if (v === undefined || v === null) return "";
  return v;
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
