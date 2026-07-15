# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

### Builder Stage
FROM golang:1.25-alpine3.21 AS builder

RUN apk --no-cache update && apk --no-cache add make

# The CO-RE eBPF object (internal/sensor/agentknox_bpfel.o) is committed and
# embedded via go:embed, so the image build needs no clang/llvm.
WORKDIR /src
COPY . .

ARG VERSION=dev
RUN go mod download && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION}" -o /out/agentknox ./cmd/agentknox && \
    CGO_ENABLED=0 go build -trimpath -o /out/akctl ./cmd/akctl && \
    CGO_ENABLED=0 go build -trimpath -o /out/agentknox-aggregator ./cmd/agentknox-aggregator

### Final Stage
FROM alpine:3.21

RUN apk --no-cache update && apk --no-cache add ca-certificates && rm -rf /var/cache/apk/*

COPY --from=builder /out/agentknox /usr/local/bin/agentknox
COPY --from=builder /out/akctl /usr/local/bin/akctl
COPY --from=builder /out/agentknox-aggregator /usr/local/bin/agentknox-aggregator

# Default entrypoint is the agent daemon; the aggregator image overrides it.
ENTRYPOINT ["/usr/local/bin/agentknox"]
