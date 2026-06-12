# FileDessect

**Upload any file. FileDessect dissects it, reverse-engineers it, and tells you
whether it's clean, suspicious, or malicious — and explains why.**

FileDessect is a self-contained, Docker-packaged file-analysis platform. A user
uploads a file through the web UI; the backend statically dissects it inside the
container (it **never executes** the sample), reverse-engineers compiled
binaries, hunts for hidden/embedded code, runs signature and heuristic checks,
and links the file's hash to its VirusTotal reputation. The result is a single
verdict with a plain-English explanation backed by detailed, evidence-bearing
findings.

---

## Features

### Verdict & explanation
- Overall verdict — **clean / suspicious / malicious** — from a weighted risk
  score plus hard overrides (e.g. a VirusTotal detection or a weaponised macro).
- Plain-English explanation citing the specific findings that drove the verdict.
- Every finding has a severity, a category, a human description of *why it
  matters*, and structured evidence.

### File identification
- MD5 / SHA-1 / SHA-256 hashing.
- True file-type detection via libmagic (independent of the extension).
- **Masquerading detection**: extension/content mismatches and deceptive double
  extensions (e.g. `invoice.pdf.exe`).

### Reverse engineering of compiled executables
- **Windows PE** (`pefile`): imported APIs translated into human capabilities
  ("can inject code into other processes", "can capture keystrokes"), section
  layout & entropy, packer detection (UPX/ASPack/Themida/VMProtect…),
  writable+executable sections, TLS callbacks, Authenticode signature presence,
  faked compile timestamps.
- **Linux ELF** (`pyelftools`): architecture, symbol-derived capabilities,
  stripped/static detection, RWX segments.

### Hidden / embedded content
- Detects executables, archives, scripts and PDFs **embedded inside** other
  files (polyglots, droppers).
- Flags data **appended after a file's logical end** (steganography / stego
  loaders) and reports the hidden region's entropy.
- Surfaces large base64 blobs and entropy-based packing.

### Content & document analysis
- Indicator extraction: URLs, IPs, domains, suspicious API/command keywords
  (injection, persistence, anti-analysis, ransomware, credential theft).
- **Office documents** (`oletools`): VBA macro detection and malicious
  auto-execute + suspicious-action pattern recognition.

### Signatures & reputation
- **YARA** scanning with bundled behaviour-oriented rules in [`rules/`](rules/)
  — drop in your own `.yar`/`.yara` files to extend coverage.
- **VirusTotal**: a reputation permalink for every file (by SHA-256), plus live
  engine-detection counts when a `VT_API_KEY` is configured. Only the **hash**
  is sent to VirusTotal — never the file content.

---

## Quick start (Docker)

```bash
# 1. (optional) enable live VirusTotal lookups
cp .env.example .env
echo "VT_API_KEY=your_key_here" >> .env

# 2. build & run
docker compose up --build

# 3. open the UI
open http://localhost:8000
```

Then drag a file onto the page. Without a `VT_API_KEY`, every other feature
still works and you get a VirusTotal reputation link for the file's hash.

### Run without compose

```bash
docker build -t filedessect .
docker run --rm -p 8000:8000 -e VT_API_KEY="$VT_API_KEY" filedessect
```

---

## Security model

- **Samples are never executed.** Every analyzer only *reads* file bytes.
- Runs as an unprivileged user; the compose service uses a read-only root
  filesystem, `no-new-privileges`, and a tmpfs scratch space.
- Uploaded samples are written to an isolated random path for the duration of
  analysis and deleted immediately afterwards (not retained by default).
- For maximum isolation when handling live malware, run the container on a host
  with no inbound exposure and disable outbound networking (set no `VT_API_KEY`)
  so nothing leaves the sandbox.

> ⚠️ Static analysis cannot prove a file is safe. A "clean" verdict means *no
> suspicious traits were found*, not a guarantee. Treat verdicts as triage, not
> ground truth.

---

## API

| Method | Path           | Description                                   |
|--------|----------------|-----------------------------------------------|
| `GET`  | `/`            | Web UI                                         |
| `GET`  | `/api/health`  | Liveness + which optional capabilities are on  |
| `POST` | `/api/analyze` | `multipart/form-data` with `file`; returns JSON report |

```bash
curl -F "file=@suspicious.exe" http://localhost:8000/api/analyze | jq .verdict
```

The JSON report contains `verdict`, `risk_score`, `explanation`, `summary`
(severity counts), `identity` (hashes/type), per-analyzer `analyzers`, and the
flattened `findings` list (each with `id`, `severity`, `description`, `data`).

---

## Architecture

```
backend/
  main.py              FastAPI app: /api/analyze, /api/health, static UI
  engine.py            Orchestrates analyzers, computes verdict + explanation
  config.py            Env-driven settings
  analyzers/
    base.py            Finding / Severity / Verdict / Analyzer framework
    identity.py        Hashes, file typing, masquerade detection
    content.py         Entropy, IOCs, suspicious-keyword heuristics
    embedded.py        Hidden/embedded content & trailing-data detection
    pe.py              Windows PE reverse engineering
    elf.py             Linux ELF reverse engineering
    office.py          VBA macro analysis (oletools)
    yara_scan.py       YARA signature matching
    virustotal.py      Hash reputation (link + optional live lookup)
  static/              Self-contained web UI (HTML/CSS/JS)
rules/                 Bundled YARA rules (extensible)
tests/                 Engine smoke/behaviour tests
```

The analyzer pipeline is plugin-style: each analyzer emits `Finding`s with a
severity weight; the engine sums weights into a risk score and maps it (with a
few hard overrides) to the final verdict. Adding a new detector is a matter of
subclassing `Analyzer` and registering it in `engine.py`.

---

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                                   # run the test suite
uvicorn backend.main:app --reload           # run locally on :8000
```

The pure-Python analyzers (identity, content, embedded) run anywhere; PE/ELF/
YARA/Office/libmagic require their native libraries, which the Docker image
installs. When a library is missing, that analyzer degrades gracefully and
`/api/health` reports the capability as off.
