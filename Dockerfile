# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git

ENV GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/os-cve-cache ./cmd/os-cve-cache

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget \
    && mkdir -p /data /app

WORKDIR /app
COPY --from=builder /out/os-cve-cache /app/os-cve-cache
COPY config.example.yaml /app/config.example.yaml
COPY docker/config.yaml /app/config.yaml
COPY docker/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
ENV ADDR=:8080
ENV CONFIG_PATH=/app/config.yaml
VOLUME ["/data"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["serve"]
