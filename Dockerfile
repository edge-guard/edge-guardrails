FROM rust:1.82 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM python:3.10-slim
WORKDIR /app
COPY --from=builder /app /app
# flask was listed here but never imported anywhere in this repo -
# dashboard_server.py is plain stdlib http.server. requests is only used by
# examples/ollama_stream_guard.py, kept for parity with requirements.txt.
RUN pip install --no-cache-dir requests
EXPOSE 8080
ENV PORT=8080
CMD ["python3", "dashboard_server.py"]
