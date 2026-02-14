#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  VERSION="v0.0.0-local.$(date -u +%Y%m%d%H%M%S)"
fi
if [[ "${VERSION}" != v* ]]; then
  echo "error: version must start with 'v' (got: ${VERSION})" >&2
  exit 1
fi

build_one() {
  local goos="$1" goarch="$2"
  local outdir="dist/${VERSION}/${goos}-${goarch}"
  mkdir -p "${outdir}"
  echo "[package] build ${goos}/${goarch}"
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o "${outdir}/sisumail-relay" ./cmd/sisumail-relay
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o "${outdir}/sisumail-tier2" ./cmd/sisumail-tier2
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o "${outdir}/sisumail" ./cmd/sisumail

  tar -C "${outdir}" -czf "dist/sisumail_${VERSION}_${goos}_${goarch}.tar.gz" sisumail-relay sisumail-tier2 sisumail
}

rm -rf "dist/${VERSION}"
mkdir -p "dist/${VERSION}"

build_one linux amd64
build_one linux arm64
build_one darwin amd64
build_one darwin arm64

echo "[package] checksums"
(
  cd dist
  sha256sum "sisumail_${VERSION}_"*.tar.gz > "sha256sum_${VERSION}.txt"
)

echo "[package] done"
echo "Artifacts:"
ls -1 "dist/sisumail_${VERSION}_"*.tar.gz
echo "Checksum file: dist/sha256sum_${VERSION}.txt"
