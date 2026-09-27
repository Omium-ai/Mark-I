#!/usr/bin/env bash
# fetch-rm-runtime.sh <triple> <dest>: the pinned llama.cpp CPU build that mark1d supervises as mark1-rm (llama-server + its libs), sha256-verified.
set -euo pipefail
triple=$1
dest=$2
tag=b11193
case "$triple" in
  x86_64-unknown-linux-gnu)  asset=llama-$tag-bin-ubuntu-x64.tar.gz;   sha=def277c3a4f0c5e2ec3b1413971878d7d5e7da7eee64f5120a0cd8f024f5a364 ;;
  aarch64-unknown-linux-gnu) asset=llama-$tag-bin-ubuntu-arm64.tar.gz; sha=e3f4b6d0ded893495b1e8767e8137f2825d1a79372254def1b3d762a054b4aa8 ;;
  x86_64-apple-darwin)       asset=llama-$tag-bin-macos-x64.tar.gz;    sha=742e2141bbf7a277f4a128f222fb7bf4f8a449b35a36b3e41db51bf8db90b4c4 ;;
  aarch64-apple-darwin)      asset=llama-$tag-bin-macos-arm64.tar.gz;  sha=d95b9af91fcf519db2c9fba9068ba75d4e858df35c8e6a08bec3e10055bb4fe2 ;;
  x86_64-pc-windows-msvc)    asset=llama-$tag-bin-win-cpu-x64.zip;     sha=1110e183589e0e2ac5b365fb5c3c4a7e149e0760c1989cac18ee426b08e5813a ;;
  *) echo "fetch-rm-runtime: no pinned runtime for $triple" >&2; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/$asset" "https://github.com/ggml-org/llama.cpp/releases/download/$tag/$asset"
got=$(cmake -E sha256sum "$tmp/$asset" | cut -d' ' -f1)
[ "$got" = "$sha" ] || { echo "fetch-rm-runtime: $asset sha256 $got, pinned $sha" >&2; exit 1; }
(cd "$tmp" && cmake -E tar xf "$asset")
srv=$(find "$tmp" -type f \( -name llama-server -o -name llama-server.exe \) | head -1)
[ -n "$srv" ] || { echo "fetch-rm-runtime: no llama-server in $asset" >&2; exit 1; }
mkdir -p "$dest"
cp "$srv" "$dest/"
find "$(dirname "$srv")" -maxdepth 1 \( -name '*.so*' -o -name '*.dylib' -o -name '*.dll' -o -name 'LICENSE*' \) -exec cp -P {} "$dest/" \;
echo "llama.cpp $tag $asset sha256:$sha" > "$dest/PINNED"
ls -l "$dest"
