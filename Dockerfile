FROM rust:1.77 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM python:3.10-slim
WORKDIR /app
COPY --from=builder /app /app
RUN pip install --no-cache-dir flask requests
EXPOSE 8080
ENV PORT=8080
CMD ["python3", "dashboard_server.py"]
