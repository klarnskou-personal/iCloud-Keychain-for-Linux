#!/usr/bin/env bash
# Register the native-messaging host with Chromium-family browsers and Firefox.
#
# Usage: host/install.sh [CHROME_EXTENSION_ID]
#
# Chromium-family browsers derive an unpacked extension's ID deterministically from the absolute
# path of its folder (SHA-256 of the path, first 128 bits, hex digits mapped to a-p), so when no
# ID is given we compute it for ./extension. Pass the ID explicitly if your browser shows a
# different one (e.g. you loaded the extension from a copy elsewhere).
#
# Firefox is keyed by the fixed gecko id in the manifest, so it needs no per-install id.
#
# Writes the host manifest into each browser's NativeMessagingHosts dir, pointing at the
# launcher in this repo. Re-run after moving the repo.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="$REPO/host/icp-host.sh"
chmod +x "$LAUNCHER"

# Must match browser_specific_settings.gecko.id in extension/manifest.json.
GECKO_ID="icp-linux@local"
HOST_NAME="org.icp.native"
installed=0

chrome_id_for_path() {  # $1 = extension dir -> the ID Chromium assigns when loaded unpacked
  printf '%s' "$(realpath "$1")" | sha256sum | cut -c1-32 | tr '0123456789abcdef' 'abcdefghijklmnop'
}

if [ -n "${1:-}" ]; then
  EXT_ID="$1"
else
  EXT_ID="$(chrome_id_for_path "$REPO/extension")"
  echo "Chromium extension id (computed from $REPO/extension): $EXT_ID"
fi

write_manifest() {  # $1 = manifest JSON, $2 = target dir (created if absent)
  local manifest="$1" dir="$2"
  mkdir -p "$dir"
  printf '%s\n' "$manifest" > "$dir/$HOST_NAME.json"
  echo "installed: $dir/$HOST_NAME.json"
  installed=$((installed + 1))
}

# Chromium-family browsers create their config dir on first run, so its presence is a fair
# proxy for "installed". Skip browsers that aren't there rather than littering config dirs.
install_if_present() {  # $1 = manifest JSON, $2 = target NativeMessagingHosts dir
  local dir="$2"
  [ -d "$(dirname "$dir")" ] || return 0
  write_manifest "$1" "$dir"
}

# --- Chromium-family (Chrome, Chromium, Helium, Brave, Edge, Vivaldi) ---
CHROME_MANIFEST="$(sed -e "s#__HOST_LAUNCHER__#$LAUNCHER#" \
                       -e "s#__EXTENSION_ID__#$EXT_ID#" \
                       "$REPO/host/org.icp.native.json.template")"
for d in \
  "$HOME/.config/google-chrome/NativeMessagingHosts" \
  "$HOME/.config/chromium/NativeMessagingHosts" \
  "$HOME/.config/helium/NativeMessagingHosts" \
  "$HOME/.config/net.imput.helium/NativeMessagingHosts" \
  "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts" \
  "$HOME/.config/microsoft-edge/NativeMessagingHosts" \
  "$HOME/.config/vivaldi/NativeMessagingHosts"; do
  install_if_present "$CHROME_MANIFEST" "$d"
done

# --- Firefox (keyed by the fixed gecko id, so no per-install id needed) ---
FIREFOX_MANIFEST="$(sed -e "s#__HOST_LAUNCHER__#$LAUNCHER#" \
                        -e "s#__GECKO_ID__#$GECKO_ID#" \
                        "$REPO/host/org.icp.native.firefox.json.template")"
if command -v firefox >/dev/null 2>&1 || [ -d "$HOME/.mozilla" ]; then
  write_manifest "$FIREFOX_MANIFEST" "$HOME/.mozilla/native-messaging-hosts"
fi
if command -v librewolf >/dev/null 2>&1 || [ -d "$HOME/.librewolf" ]; then
  write_manifest "$FIREFOX_MANIFEST" "$HOME/.librewolf/native-messaging-hosts"
fi

if [ "$installed" -eq 0 ]; then
  echo "No supported browser config dir found; nothing installed." >&2
  exit 1
fi
echo "Done. Load/reload the extension; if its ID differs from $EXT_ID, re-run: host/install.sh <ID>"
