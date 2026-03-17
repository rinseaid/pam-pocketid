FROM golang:1.25 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /app/pam-pocketid .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 python3-pip && \
    pip3 install --no-cache-dir --break-system-packages onepassword-sdk==0.4.0 && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r pampocketid && useradd -r -g pampocketid -s /sbin/nologin pampocketid

COPY --from=builder /app/pam-pocketid /usr/local/bin/pam-pocketid

USER pampocketid
EXPOSE 8090

ENTRYPOINT ["pam-pocketid", "serve"]
