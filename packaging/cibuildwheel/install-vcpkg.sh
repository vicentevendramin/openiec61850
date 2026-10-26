#!/usr/bin/env bash
# Installs vcpkg (pinned to the builtin-baseline of vcpkg.json) for cibuildwheel's before-all step.
# Usage: install-vcpkg.sh <vcpkg-root>
# Linux runs inside the manylinux_2_28 container (AlmaLinux 8): install the tools vcpkg needs
# first. macOS and Windows runners already have them.
set -euo pipefail

root="${1:?usage: install-vcpkg.sh <vcpkg-root>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
baseline="$(sed -n 's/.*"builtin-baseline": *"\([0-9a-f]*\)".*/\1/p' "$here/../../vcpkg.json")"

if [[ "$(uname -s)" == Linux ]]; then
  if command -v dnf > /dev/null; then
    dnf install -y -q zip unzip curl tar git pkgconfig perl make
  elif command -v yum > /dev/null; then
    yum install -y -q zip unzip curl tar git pkgconfig perl make
  fi
  # VCPKG_FORCE_SYSTEM_BINARIES needs cmake and ninja on PATH: manylinux ships cmake through
  # pipx; ninja comes from PyPI.
  command -v ninja > /dev/null || pipx install ninja > /dev/null 2>&1 || python3 -m pip install -q ninja
fi

if [[ ! -x "$root/vcpkg" && ! -x "$root/vcpkg.exe" ]]; then
  git clone -q https://github.com/microsoft/vcpkg.git "$root"
  git -C "$root" checkout -q "$baseline"
  case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) cmd //c "$(cygpath -w "$root")\\bootstrap-vcpkg.bat" -disableMetrics ;;
    *) "$root/bootstrap-vcpkg.sh" -disableMetrics ;;
  esac
fi
