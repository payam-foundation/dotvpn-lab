#!/bin/sh
# Runs the packet-level suites in the lab container. Binaries are cross-built
# on the host, so the container needs no Go toolchain. Run from dotvpn-lab.
# Usage: docker/lab.sh [go test args, default: ./suites/netns ./suites/leak ...]
set -eu
cd "$(dirname "$0")/.."
ARCH="$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/;s/x86_64/amd64/')"
OUT="$PWD/out"
BINS="$OUT/bin"
rm -rf "$OUT/tests"
mkdir -p "$BINS" "$OUT/tests"
export CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH"
build() { (cd "$1" && go build -trimpath ${4:+-tags "$4"} -o "$2" "$3"); }
build ../dotvpn-core "$BINS/core-e2e" ./cmd/dotvpn-core e2e
build ../dotvpn-core "$BINS/core" ./cmd/dotvpn-core
build ../dotvpn-relay "$BINS/relay" ./cmd/dotvpn-relay
build ../dotvpn-client "$BINS/dotvpn" ./cmd/dotvpn
build . "$BINS/labtool" ./cmd/labtool
pkgs="${*:-./suites/netns}"
for p in $pkgs; do
  go test -c -tags lab -trimpath -o "$OUT/tests/$(basename "$p").test" "$p"
done
docker build -q -t dotvpn-lab:dev -f docker/Dockerfile.lab docker >/dev/null
# Namespaces and NFQUEUE need NET_ADMIN and SYS_ADMIN, not --privileged.
docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN --device /dev/net/tun \
  -e LAB_BINS=/lab/out/bin -e LAB_ROOT=/lab -e LAB_OUT=out ${LAB_ENV:-} \
  -v "$PWD:/lab" -w /lab dotvpn-lab:dev \
  sh -c 'rc=0; for t in /lab/out/tests/*.test; do echo "== $t"; (cd /lab/suites/$(basename $t .test) && "$t" -test.v -test.count=1 -test.timeout=20m ${LAB_RUN:+-test.run "$LAB_RUN"}) || rc=1; done; exit $rc'
