FROM python:3.12-slim

# System dependencies for the analysis engine:
#   libmagic1   -> file type identification (python-magic)
#   libyara*    -> YARA signature scanning (yara-python)
#   binutils    -> objdump / strings for native binary inspection
#   ssdeep      -> fuzzy hashing helpers used by oletools
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
        binutils \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Rizin — the open-source reverse-engineering engine that powers the Cutter GUI.
# It drives the `cutter` analyzer (function listing, per-function disassembly,
# import->caller cross-references, and — with a decompiler plugin — pseudo-C) and
# the opt-in interactive disassembly endpoints (INTERACTIVE_DISASM=true).
#
# Rizin is NOT packaged in Debian bookworm (this image's base), so we install the
# upstream self-contained static build from the official GitHub release rather
# than apt. On amd64 the install is verified and the build FAILS if rizin is
# missing, so the image can never silently ship without the engine. On other
# architectures (no static linux release) we fall back to apt tolerantly.
#
# For decompilation, additionally install the `rz-ghidra` plugin in your image
# (e.g. `rz-pm install rz-ghidra`); it is optional and detected at runtime.
ARG RIZIN_VERSION=0.8.2
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    if [ "$arch" = "amd64" ]; then \
        apt-get update; \
        apt-get install -y --no-install-recommends curl xz-utils ca-certificates; \
        curl -fsSL -o /tmp/rizin.tar.xz \
          "https://github.com/rizinorg/rizin/releases/download/v${RIZIN_VERSION}/rizin-v${RIZIN_VERSION}-static-x86_64.tar.xz"; \
        mkdir -p /tmp/rz; \
        tar -xJf /tmp/rizin.tar.xz -C /tmp/rz; \
        cp -a /tmp/rz/bin/rizin /usr/local/bin/rizin; \
        cp -a /tmp/rz/share/. /usr/local/share/; \
        rm -rf /tmp/rizin.tar.xz /tmp/rz; \
        apt-get purge -y curl xz-utils; apt-get autoremove -y; \
        rm -rf /var/lib/apt/lists/*; \
        rizin -v; \
    else \
        apt-get update; \
        (apt-get install -y --no-install-recommends rizin || \
          echo "rizin unavailable for $arch; deep analysis disabled (Capstone still used)"); \
        rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /app

# Install Python dependencies first to leverage Docker layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code and signatures.
COPY backend ./backend
COPY rules ./rules

# Run the analysis sandbox as an unprivileged user. Uploaded, potentially
# malicious files are only ever read (never executed), but dropping
# privileges adds defence in depth.
RUN useradd --create-home --uid 10001 dessect \
    && mkdir -p /app/uploads \
    && chown -R dessect:dessect /app
USER dessect

ENV PYTHONUNBUFFERED=1 \
    UPLOAD_DIR=/app/uploads

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
