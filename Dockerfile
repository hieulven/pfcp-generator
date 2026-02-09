## Build stage: UBI 8 with Go and libpcap-devel
FROM registry.access.redhat.com/ubi8/ubi:8.10 AS builder

ARG GO_VERSION=1.25.7

# Install build dependencies
RUN dnf install -y gcc make libpcap-devel tar gzip && \
    dnf clean all

# Install Go from official tarball (RHEL 8 repos may not carry this version)
RUN arch=$(uname -m) && \
    case "$arch" in \
      x86_64)  goarch=amd64 ;; \
      aarch64) goarch=arm64 ;; \
      *)       echo "unsupported arch: $arch" && exit 1 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" \
      -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV CGO_ENABLED=1

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags "-X main.version=1.0.0" -o pfcp-generator ./cmd/pfcp-generator/ && \
    go build -o mockupf ./test/mockupf/

## Runtime stage: minimal UBI 8 with libpcap
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.10

RUN microdnf install -y libpcap && microdnf clean all

COPY --from=builder /build/pfcp-generator /usr/local/bin/pfcp-generator
COPY --from=builder /build/mockupf /usr/local/bin/mockupf

ENTRYPOINT ["pfcp-generator"]
