# Build the manager binary
# Use BUILDPLATFORM to compile natively (faster than QEMU emulation)
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27@sha256:7543a96ce82c8e9003cae079ee3e0bc5b7799df8eed2a041e403af0d31fa4e67 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /workspace

# Copy Go module files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies - this layer is cached if go.mod/go.sum don't change.
# The module proxy occasionally resets an HTTP/2 stream under CI load; retry the
# complete download a bounded number of times so a transient network failure
# does not discard an otherwise reusable image build.
RUN for attempt in 1 2 3 4 5; do \
      if go mod download; then \
        exit 0; \
      fi; \
      if [ "${attempt}" -lt 5 ]; then \
        echo "go mod download failed (attempt ${attempt}/5); retrying" >&2; \
        sleep $((attempt * 5)); \
      fi; \
    done; \
    exit 1

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build for the target platform using Go's native cross-compilation
# CGO_ENABLED=0 ensures static binary (no C dependencies)
# -ldflags injects version information at build time
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a \
    -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o manager ./cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Supports: linux/amd64, linux/arm64, linux/arm, linux/s390x, linux/ppc64le
FROM gcr.io/distroless/static:nonroot@sha256:e754765ad9e167b0677b41c617fd44afb7b9818a477f48f17bda08e12cfb98cb
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
