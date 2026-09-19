# =============================================================================
# EdgeGuard SDK - multi-stage image for the audit dashboard
# =============================================================================
#
# What the previous version did wrong, and why each is fixed below:
#
#   * `COPY . .` into the builder copied the host's `target/` and `.venv/`
#     into the build context, so a local debug build was shipped inside the
#     image and every source edit invalidated the dependency layer.
#   * `COPY --from=builder /app /app` then carried the entire Rust toolchain
#     output - sources, object files, the 4.8 MB dylib AND its intermediates -
#     into the runtime image.
#   * It ran as root.
#   * It never built the Python extension. `dashboard_server.py` imports
#     nothing from `edgeguard`, so this happened to work, but any example or
#     middleware in the image would fail with ImportError at runtime.
#
# Build:   docker build -t edgeguard:0.8.0 .
# Run:     docker run --rm -p 127.0.0.1:8080:8080 \
#            -e EDGEGUARD_DASHBOARD_TOKEN=$(openssl rand -hex 32) \
#            -v edgeguard-data:/data edgeguard:0.8.0
#
# The dashboard authenticates every request and binds loopback INSIDE the
# container; publishing it as `-p 127.0.0.1:8080:8080` keeps that true on the
# host. Publishing it as `-p 8080:8080` exposes it on every host interface -
# the token still applies, but do not do that without a TLS terminator.

# -----------------------------------------------------------------------------
# Stage 1 - build the wheel
# -----------------------------------------------------------------------------
FROM rust:1.82-slim-bookworm AS builder

# maturin needs a Python interpreter and headers to build the extension.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-dev python3-pip \
 && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --break-system-packages maturin==1.7.4

WORKDIR /build

# Dependency layer first. Cargo needs a source file to resolve and build the
# dependency graph, so a stub lib.rs stands in for the real one; it is
# overwritten below. This layer only rebuilds when the manifests change, which
# is what keeps an ordinary source edit off the ~2 minute dependency build.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/lib.rs \
 && cargo build --release --features python 2>/dev/null || true

# Now the real sources. `.dockerignore` keeps target/, .venv/ and the audit
# databases out of the context entirely.
COPY src ./src
COPY pyproject.toml ./
COPY policy.yaml ./

# Touch so cargo does not reuse the stub's fingerprint for the real crate.
RUN touch src/lib.rs \
 && maturin build --release --features python --out /wheels

# -----------------------------------------------------------------------------
# Stage 2 - runtime
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# `requests` only: dashboard_server.py is plain stdlib http.server, and
# requests is used by examples/ollama_stream_guard.py. Flask was listed in an
# earlier version and is imported nowhere in this repository.
RUN pip install --no-cache-dir requests==2.32.3

COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Non-root. A fixed uid/gid rather than a name lookup so a bind-mounted volume
# has predictable ownership on the host.
RUN groupadd --gid 10001 edgeguard \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin edgeguard

WORKDIR /app
COPY --chown=root:root dashboard_server.py policy.yaml ./

# The audit database is the one thing the process must write, and it is the
# file that leaked in the pre-hardening dashboard. It lives on a volume owned
# by the runtime user, NOT in /app - so the application directory can stay
# read-only and nothing writable is ever inside the served tree.
RUN mkdir -p /data && chown 10001:10001 /data
VOLUME ["/data"]
ENV EDGEGUARD_AUDIT_DB=/data/native_edge_queue.db

USER 10001:10001

# Loopback inside the container; see the header for how to publish it.
ENV PORT=8080 \
    EDGEGUARD_DASHBOARD_BIND=127.0.0.1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
EXPOSE 8080

# Proves the extension actually imports, which the previous image never did.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python3 -c "import edgeguard; edgeguard.EdgeGuard(db_path=None).scan('ping')" || exit 1

CMD ["python3", "dashboard_server.py"]
