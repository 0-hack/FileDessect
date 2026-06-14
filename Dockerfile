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

# Optional: Rizin — the open-source reverse-engineering engine that powers the
# Cutter GUI. When present, FileDessect enriches its disassembly with Rizin's
# function analysis. Installed tolerantly so the image still builds where the
# package is unavailable (the Capstone engine is always used regardless).
RUN apt-get update \
    && (apt-get install -y --no-install-recommends rizin || \
        echo "rizin unavailable in this base image; continuing without it") \
    && rm -rf /var/lib/apt/lists/*

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
