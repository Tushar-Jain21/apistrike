# APIStrike — reproducible container (100% open source)
# HTML/PDF reporting (WeasyPrint) needs native Pango/Cairo libs, so we install
# them explicitly. Multi-purpose: run any apistrike subcommand via the entrypoint.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

# --- System libraries required by WeasyPrint (HTML -> PDF) + base fonts -------
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libgdk-pixbuf-2.0-0 \
        libcairo2 \
        libffi8 \
        libjpeg62-turbo \
        shared-mime-info \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Python dependencies first (better layer caching) -------------------------
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- Application source -------------------------------------------------------
COPY . .

# --- Non-root runtime user + writable work dir --------------------------------
RUN useradd --create-home --uid 10001 apistrike \
    && mkdir -p /work \
    && chown -R apistrike:apistrike /app /work
USER apistrike

# Users mount their engagement dir (scope.yaml, specs, reports) at /work.
# findings.db and reports/ are written here so they persist on the host.
WORKDIR /work
VOLUME ["/work"]

# `docker run apistrike <args>` -> `python -m apistrike <args>`
ENTRYPOINT ["python", "-m", "apistrike"]
CMD ["--help"]
