ARG GO_BUILDER_IMAGE=golang:1.26.3-bookworm@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b
ARG GLIBC_RUNTIME_IMAGE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

FROM --platform=$BUILDPLATFORM ${GO_BUILDER_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd/web/tools ./cmd/web/tools
COPY cmd/worker-relay ./cmd/worker-relay
COPY cmd/worker-preflight ./cmd/worker-preflight
COPY cmd/worker-web-probe ./cmd/worker-web-probe
COPY internal ./internal
RUN export CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    && go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/argos-worker-relay ./cmd/worker-relay \
    && go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/argos-worker-preflight ./cmd/worker-preflight \
    && go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/argos-worker-probe ./cmd/worker-web-probe \
    && chmod 0755 /out/argos-worker-relay \
    && chmod 0755 /out/argos-worker-preflight \
    && chmod 0755 /out/argos-worker-probe \
    && mkdir -p /image-root/run/argos /image-root/workspace /image-root/tmp \
    && touch /image-root/run/argos/.keep /image-root/workspace/.keep /image-root/tmp/.keep \
    && chown -R 65532:65532 /image-root \
    && chmod 1777 /image-root/tmp

FROM ${GLIBC_RUNTIME_IMAGE} AS worker
ARG ARGOS_WORKER_VERSION=dev
ARG ARGOS_WORKER_REVISION=unknown
ARG ARGOS_NODE_VERSION=24.21.0
ARG ARGOS_NODE_SHA256_AMD64=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6
ARG ARGOS_NODE_SHA256_ARM64=6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2
ARG ARGOS_PLAYWRIGHT_VERSION=1.64.0
ARG TARGETARCH
LABEL org.opencontainers.image.title="Argos isolated audit worker" \
      org.opencontainers.image.version=${ARGOS_WORKER_VERSION} \
      org.opencontainers.image.revision=${ARGOS_WORKER_REVISION} \
      org.opencontainers.image.source="https://github.com/iwiels/ARGOS" \
      org.opencontainers.image.base.name="debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587"
COPY worker/browser/package.json worker/browser/package-lock.json /opt/argos/browser/
COPY worker/browser/browser-worker.mjs /usr/local/bin/argos-browser-worker
ENV HOME=/tmp TMPDIR=/tmp PATH=/opt/argos/node/bin:/usr/local/bin:/usr/bin:/bin PLAYWRIGHT_BROWSERS_PATH=/opt/argos/browsers \
    ARGOS_PLAYWRIGHT_MODULE=/opt/argos/browser/node_modules/playwright-core/index.mjs \
    ARGOS_WORKER_VERSION=${ARGOS_WORKER_VERSION} ARGOS_PLAYWRIGHT_VERSION=${ARGOS_PLAYWRIGHT_VERSION}
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) node_arch=x64; node_sha="$ARGOS_NODE_SHA256_AMD64"; node_archive=/tmp/node-amd64.tar.xz ;; \
      arm64) node_arch=arm64; node_sha="$ARGOS_NODE_SHA256_ARM64"; node_archive=/tmp/node-arm64.tar.xz ;; \
      *) echo "unsupported worker architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl xz-utils; \
    node_archive="/tmp/node-${node_arch}.tar.xz"; \
    curl --fail --location --silent --show-error "https://nodejs.org/download/release/v${ARGOS_NODE_VERSION}/node-v${ARGOS_NODE_VERSION}-linux-${node_arch}.tar.xz" -o "$node_archive"; \
    printf '%s  %s\n' "$node_sha" "$node_archive" | sha256sum -c -; \
    mkdir -p /opt/argos/node; \
    tar -xJf "$node_archive" -C /opt/argos/node --strip-components=1; \
    test "$(/opt/argos/node/bin/node --version)" = "v$ARGOS_NODE_VERSION"; \
    test "$(/opt/argos/node/bin/npm --version)"; \
    chmod 0755 /usr/local/bin/argos-browser-worker; \
    npm ci --prefix /opt/argos/browser --omit=dev --ignore-scripts --no-audit --no-fund; \
    test "$(node -e 'process.stdout.write(require("/opt/argos/browser/node_modules/playwright-core/package.json").version)')" = "$ARGOS_PLAYWRIGHT_VERSION"; \
    node /opt/argos/browser/node_modules/playwright-core/cli.js install --with-deps chromium; \
    mkdir -p /usr/share/doc/argos-browser/licenses/playwright /usr/share/doc/argos-browser/licenses/chromium; \
    cp /opt/argos/browser/node_modules/playwright-core/LICENSE /usr/share/doc/argos-browser/licenses/playwright/LICENSE; \
    chromium_license="$(find /opt/argos/browsers -type f -name LICENSES.chromium.html -print -quit)"; \
    if [ -n "$chromium_license" ]; then \
      cp "$chromium_license" /usr/share/doc/argos-browser/licenses/chromium/LICENSES.chromium.html; \
    else \
      chromium_binary="$(node -p 'require("/opt/argos/browser/node_modules/playwright-core").chromium.executablePath()')"; \
      "$chromium_binary" --no-sandbox --credits > /usr/share/doc/argos-browser/licenses/chromium/LICENSES.chromium.html; \
    fi; \
    test -s /usr/share/doc/argos-browser/licenses/chromium/LICENSES.chromium.html; \
    npm cache clean --force; \
    rm -f "$node_archive"; \
    rm -rf /var/lib/apt/lists/* /root/.npm /root/.cache; \
    chmod -R a+rX /opt/argos
COPY --from=build /out/argos-worker-relay /usr/local/bin/argos-worker-relay
COPY --from=build /out/argos-worker-preflight /usr/local/bin/argos-worker-preflight
COPY --from=build /out/argos-worker-probe /usr/local/bin/argos-worker-probe
COPY --from=build --chown=65532:65532 /image-root/ /
WORKDIR /workspace
USER 65532:65532
