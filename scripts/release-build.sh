#!/bin/sh
# Build one reproducible static release archive plus its CycloneDX SBOM.
# usage: scripts/release-build.sh TAG GOOS GOARCH OUTDIR
# Output: OUTDIR/verdict_<ver>_<os>_<arch>.tar.gz (.zip on windows) and
#         OUTDIR/verdict_<ver>_<os>_<arch>.cdx.json
# Run from a clean checkout of the tag; the VCS stamp records the commit.
set -eu

tag=$1 goos=$2 goarch=$3 out=$4
ver=${tag#v}
name=verdict_${ver}_${goos}_${goarch}
root=$(pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

exe=verdict
[ "$goos" = windows ] && exe=verdict.exe

CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build \
  -trimpath -buildvcs=true \
  -ldflags "-s -w -buildid=" \
  -o "$stage/$name/$exe" ./cmd/verdict

# SBOM from the binary's embedded module list (host-run tool, stdlib only).
go run ./tools/sbom -bin "$stage/$name/$exe" -version "$ver" > "$out/$name.cdx.json"

cp LICENSE NOTICE README.md "$stage/$name/"
# Fixed mtime, owner, order and no gzip timestamp: same input, same bytes.
find "$stage/$name" -exec touch -h -d '2000-01-01T00:00:00Z' {} +
cd "$stage"
if [ "$goos" = windows ]; then
  zip -X -q -r "$out/$name.zip" "$name"
else
  tar --sort=name --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX' \
    --mtime='2000-01-01 00:00:00Z' -cf - "$name" | gzip -n -9 > "$out/$name.tar.gz"
fi
cd "$root"
