# -- Stage 1: Build the application --
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency manifests first to leverage Docker layer caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy the remaining source code
COPY . .

# Build the static binary for pkgdash-web
RUN CGO_ENABLED=0 GOOS=linux go build -o /pkgdash-web ./cmd/pkgdash-web

# -- Stage 2: Minimal runtime image --
FROM alpine:latest

# Install CA certificates for secure HTTPS API calls to pkgdashd
RUN apk --no-cache add ca-certificates tzdata

# Create a non-root user for security
RUN adduser -D -g '' appuser
USER appuser

WORKDIR /app

# Copy compiled binary from the builder stage
COPY --from=builder --chown=appuser:appuser /pkgdash-web /app/pkgdash-web

# Expose default web server port
EXPOSE 8080

# Execute the application
ENTRYPOINT ["/app/pkgdash-web"]
