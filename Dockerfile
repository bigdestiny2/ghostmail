# GhostMail - Multi-stage Docker build
# Produces a minimal Alpine image with the ghostmail binary.

# --- Build stage ---
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache make git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build

# --- Runtime stage ---
FROM alpine:3.21

RUN apk add --no-cache \
    ca-certificates \
    tor \
    && addgroup -S ghostmail \
    && adduser -S -G ghostmail -h /var/lib/ghostmail ghostmail

# Copy binaries
COPY --from=builder /src/bin/ghostmail /usr/local/bin/ghostmail
COPY --from=builder /src/bin/ghostctl /usr/local/bin/ghostctl

# Copy default config
COPY configs/ghostmail.example.toml /etc/ghostmail/ghostmail.toml

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create data directories
RUN mkdir -p /var/lib/ghostmail /etc/ghostmail/tls \
    && chown -R ghostmail:ghostmail /var/lib/ghostmail /etc/ghostmail

# Expose ports
# 25   = SMTP inbound
# 587  = SMTP submission
# 993  = IMAPS
# 8080 = Admin + Webmail panel
EXPOSE 25 587 993 8080

USER ghostmail
VOLUME ["/var/lib/ghostmail", "/etc/ghostmail"]

ENTRYPOINT ["docker-entrypoint.sh"]
CMD []
