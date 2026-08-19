# Build the manager binary
# Use BUILDPLATFORM to compile natively (faster than QEMU emulation)
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26@sha256:45a5f7a810238aabcbad211d70b9ae082022d96f7c7259e94041ad1b933575ac AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /workspace

# Copy Go module files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies - this layer is cached if go.mod/go.sum don't change
RUN go mod download

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
FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
