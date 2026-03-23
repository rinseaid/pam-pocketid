FROM golang:1.25 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
ARG VERSION=dev
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /app/pam-pocketid .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 python3-pip wget && \
    pip3 install --no-cache-dir --break-system-packages onepassword-sdk==0.4.0 apprise==1.9.1 && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r pampocketid && useradd -r -g pampocketid -s /sbin/nologin pampocketid && \
    mkdir -p /data && chown pampocketid:pampocketid /data

COPY --from=builder /app/pam-pocketid /usr/local/bin/pam-pocketid

USER pampocketid
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --spider -q http://localhost:8090/healthz || exit 1

ENTRYPOINT ["pam-pocketid", "serve"]
