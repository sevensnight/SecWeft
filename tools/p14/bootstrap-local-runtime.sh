#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
TOOL_DIR="$ROOT/.tools/p14"
BIN_DIR="$TOOL_DIR/bin"
INSTALL_MISSING=false
if [ "${1:-}" = "--install-missing" ]; then
  INSTALL_MISSING=true
fi
mkdir -p "$BIN_DIR"

find_tool() {
  name="$1"
  if [ -x "$BIN_DIR/$name" ]; then
    printf '%s\n' "$BIN_DIR/$name"
  elif command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
  else
    return 1
  fi
}

download_tool() {
  name="$1"
  if [ "$INSTALL_MISSING" != "true" ]; then
    return 1
  fi
  case "$name" in
    kind)
      curl -fsSLo "$BIN_DIR/kind" "https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64"
      chmod +x "$BIN_DIR/kind"
      ;;
    kubectl)
      curl -fsSLo "$BIN_DIR/kubectl" "https://dl.k8s.io/release/v1.32.2/bin/linux/amd64/kubectl"
      chmod +x "$BIN_DIR/kubectl"
      ;;
    helm)
      tmp="$TOOL_DIR/helm.tar.gz"
      curl -fsSLo "$tmp" "https://get.helm.sh/helm-v3.17.3-linux-amd64.tar.gz"
      tar -xzf "$tmp" -C "$TOOL_DIR"
      cp "$TOOL_DIR/linux-amd64/helm" "$BIN_DIR/helm"
      chmod +x "$BIN_DIR/helm"
      rm -f "$tmp"
      ;;
    *)
      return 1
      ;;
  esac
}

printf '{\n'
printf '  "install_missing": %s,\n' "$INSTALL_MISSING"
printf '  "tool_dir": "%s",\n' "$TOOL_DIR"
printf '  "checks": [\n'
first=true
valid=true
for tool in docker wsl kind k3d kubectl helm python node pnpm; do
  resolved=""
  if resolved="$(find_tool "$tool" 2>/dev/null)"; then
    :
  elif download_tool "$tool" 2>/dev/null && resolved="$(find_tool "$tool" 2>/dev/null)"; then
    :
  else
    resolved=""
  fi
  available=false
  version=""
  if [ -n "$resolved" ]; then
    available=true
    case "$tool" in
      docker) version="$("$resolved" version --format '{{json .}}' 2>&1 || true)" ;;
      kubectl) version="$("$resolved" version --client=true -o json 2>&1 || true)" ;;
      helm) version="$("$resolved" version --template '{{.Version}}' 2>&1 || true)" ;;
      *) version="$("$resolved" --version 2>&1 || "$resolved" version 2>&1 || true)" ;;
    esac
  elif [ "$tool" != "wsl" ] && [ "$tool" != "k3d" ]; then
    valid=false
  fi
  if [ "$first" = "true" ]; then first=false; else printf ',\n'; fi
  esc_version=$(printf '%s' "$version" | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g')
  printf '    {"tool":"%s","available":%s,"resolved":"%s","version":"%s"}' "$tool" "$available" "$resolved" "$esc_version"
done
printf '\n  ],\n'
printf '  "valid": %s\n' "$valid"
printf '}\n'
if [ "$valid" != "true" ]; then exit 1; fi
