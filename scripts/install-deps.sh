#!/usr/bin/env bash
# Install ip_checker dependencies on macOS or Linux (brew/apt + pip).
# Usage: ./scripts/install-deps.sh [minimal|full|dns|pcap|owasp|enrichment|diagnostics|scan]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GROUP="${1:-minimal}"

if [[ "$(uname -s)" == "Darwin" ]]; then
  OS="macos"
elif [[ "$(uname -s)" =~ MINGW|MSYS|CYGWIN ]]; then
  echo "On Windows use: powershell -ExecutionPolicy Bypass -File scripts/install-deps.ps1 -Profile $GROUP"
  exit 1
else
  OS="linux"
fi

run_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Install from https://brew.sh or install packages manually."
    return 1
  fi
  brew install "$@"
}

run_apt() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get not found. Install packages manually (see dependencies.manifest.json)."
    return 1
  fi
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends "$@"
}

pip_install() {
  local py="python3"
  command -v "$py" >/dev/null 2>&1 || py="python"
  "$py" -m pip install --upgrade pip
  "$py" -m pip install "$@"
}

install_core() {
  if [[ "$OS" == "macos" ]]; then
    run_brew python@3.12 whois || true
  else
    run_apt python3 python3-pip python3-venv whois iputils-ping dnsutils || true
  fi
}

install_diagnostics() {
  if [[ "$OS" == "macos" ]]; then
    : # traceroute often present
  else
    run_apt traceroute || true
  fi
}

install_scan() {
  if [[ "$OS" == "macos" ]]; then
    run_brew nmap || true
  else
    run_apt nmap || true
  fi
}

install_pcap() {
  if [[ "$OS" == "macos" ]]; then
    run_brew wireshark || true
  else
    run_apt tcpdump tshark wireshark-common || true
  fi
}

install_dns_pip() {
  pip_install -r "$REPO_ROOT/requirements-dns.txt"
}

install_enrichment_pip() {
  pip_install -r "$REPO_ROOT/requirements-optional.txt"
}

install_owasp() {
  if [[ "$OS" == "macos" ]]; then
    run_brew amass || true
  else
    echo "Amass on Linux: see https://github.com/owasp-amass/amass#installation"
  fi
  echo "Nettacker (AGPL): git clone https://github.com/OWASP/Nettacker.git \"\$HOME/Nettacker\""
}

case "$GROUP" in
  minimal|core)
    install_core
    ;;
  diagnostics)
    install_core
    install_diagnostics
    ;;
  scan)
    install_scan
    ;;
  pcap)
    install_pcap
    ;;
  dns)
    install_core
    install_dns_pip
    install_pcap
    ;;
  enrichment)
    install_enrichment_pip
    ;;
  owasp)
    install_owasp
    ;;
  full|all)
    install_core
    install_diagnostics
    install_scan
    install_pcap
    install_dns_pip
    install_enrichment_pip
    install_owasp
    ;;
  *)
    echo "Unknown group: $GROUP"
    echo "Use: minimal full dns pcap owasp enrichment diagnostics scan"
    exit 2
    ;;
esac

echo ""
echo "Running dependency check..."
python3 "$SCRIPT_DIR/check_deps.py" --group "$GROUP" --no-fail || python "$SCRIPT_DIR/check_deps.py" --group "$GROUP" --no-fail
echo "Done. For Windows: scripts/install-deps.ps1"
