#!/usr/bin/env bash
# One-shot setup for Omarchy (Arch Linux + Hyprland). Idempotent; re-run any time.
#
#   ./install-omarchy.sh [--no-anisette] [--ext-id <CHROMIUM_EXTENSION_ID>]
#
# What it does:
#   1. creates the Python venv and installs `icp` into it
#   2. runs the anisette server as a systemd *system* service via Omarchy's Docker (needs sudo once);
#      skip with --no-anisette if you already run one and set ICP_ANISETTE_URL yourself
#   3. puts `icp` on your PATH (~/.local/bin)
#   4. registers the browser native-messaging host for every Chromium-family browser / Firefox found
#
# Afterwards: `icp login`, then load ./extension as an unpacked extension in your browser.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANISETTE=1
EXT_ID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-anisette) ANISETTE=0 ;;
    --ext-id) EXT_ID="${2:-}"; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1 - install it with: sudo pacman -S $2" >&2; exit 1; }; }

step "Preflight"
need python3 python
need curl curl
[ "$ANISETTE" -eq 1 ] && need docker docker
if ! busctl --user status org.freedesktop.secrets >/dev/null 2>&1; then
  echo "note: no Secret Service (gnome-keyring) on the session bus; icp will fall back to a 0600 key file." >&2
fi

step "Python venv ($REPO/.venv)"
[ -x "$REPO/.venv/bin/python" ] || python3 -m venv "$REPO/.venv"
"$REPO/.venv/bin/pip" install -q --upgrade pip
"$REPO/.venv/bin/pip" install -q -e "$REPO"
echo "icp $("$REPO/.venv/bin/icp" --help 2>/dev/null | head -1 || echo installed)"

if [ "$ANISETTE" -eq 1 ]; then
  step "Anisette server (systemd system service, Docker, localhost:6969)"
  if ! cmp -s "$REPO/omarchy/icp-anisette.service" /etc/systemd/system/icp-anisette.service 2>/dev/null; then
    echo "Installing /etc/systemd/system/icp-anisette.service (sudo)"
    sudo install -Dm644 "$REPO/omarchy/icp-anisette.service" /etc/systemd/system/icp-anisette.service
    sudo systemctl daemon-reload
  fi
  sudo systemctl enable --now icp-anisette.service
  printf 'waiting for anisette'
  for _ in $(seq 1 90); do
    if curl -fsS --max-time 2 http://127.0.0.1:6969 >/dev/null 2>&1; then echo " - up"; break; fi
    printf '.'; sleep 2
  done
  if ! curl -fsS --max-time 2 http://127.0.0.1:6969 >/dev/null 2>&1; then
    echo; echo "anisette is not answering yet (first start pulls the image). Check: systemctl status icp-anisette" >&2
  fi
fi

step "CLI on PATH"
mkdir -p "$HOME/.local/bin"
ln -sfn "$REPO/.venv/bin/icp" "$HOME/.local/bin/icp"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "note: add ~/.local/bin to PATH" >&2 ;; esac
echo "~/.local/bin/icp -> $REPO/.venv/bin/icp"

step "Browser native-messaging host"
if [ -n "$EXT_ID" ]; then "$REPO/host/install.sh" "$EXT_ID"; else "$REPO/host/install.sh"; fi

step "Done"
cat <<MSG
Next:
  1. icp login                      # Apple ID, password, 2FA, then the device passcode (read the warning!)
  2. In Chrome/Chromium/Brave: chrome://extensions -> Developer mode -> Load unpacked -> $REPO/extension
     The host is already registered for the ID that folder gets. If the extensions page shows a
     different ID, run: $REPO/host/install.sh <ID>
  3. icp show                       # browse; the extension autofills on sign-in pages
MSG
