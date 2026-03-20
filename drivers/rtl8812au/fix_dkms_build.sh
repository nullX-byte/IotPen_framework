#!/usr/bin/env bash
# fix_dkms_build.sh
# Fixes the rtl8812au DKMS build failure on Linux kernel 6.x:
#
#   fatal error: drv_types.h: No such file or directory
#
# Root cause:
#   Starting with kernel 6.x the out-of-tree Kbuild system no longer
#   guarantees that $(src) is set to the module source directory.  The
#   rtl8812au Makefile relies on $(src) to build its EXTRA_CFLAGS include
#   paths, so the compiler cannot find the driver-private headers that live
#   in the source root (drv_types.h, hal_data.h, …).
#
# Fix applied:
#   Insert a small guard block near the top of the driver Makefile that
#   falls back to $(M) (the module tree path, reliably set by DKMS/kbuild)
#   or $(shell pwd) when $(src) is empty.
#
# Usage:
#   sudo bash fix_dkms_build.sh [--driver-version <version>] [--kernel <ver>]
#
#   --driver-version  rtl8812au DKMS version (default: 5.13.6-23)
#   --kernel          target kernel version   (default: running kernel)

set -euo pipefail

DRIVER_NAME="rtl8812au"
DRIVER_VERSION="5.13.6-23"
KERNEL_VER="$(uname -r)"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --driver-version)
            DRIVER_VERSION="$2"; shift 2 ;;
        --kernel)
            KERNEL_VER="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

SOURCE_DIR="/usr/src/${DRIVER_NAME}-${DRIVER_VERSION}"
MAKEFILE="${SOURCE_DIR}/Makefile"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: this script must be run as root (sudo)." >&2
    exit 1
fi

if [[ ! -d "${SOURCE_DIR}" ]]; then
    echo "Error: DKMS source directory not found: ${SOURCE_DIR}" >&2
    echo "       Install the driver first, e.g.:" >&2
    echo "         git clone https://github.com/aircrack-ng/rtl8812au.git \\" >&2
    echo "           /usr/src/${DRIVER_NAME}-${DRIVER_VERSION}" >&2
    echo "         dkms add -m ${DRIVER_NAME} -v ${DRIVER_VERSION}" >&2
    exit 1
fi

if [[ ! -f "${MAKEFILE}" ]]; then
    echo "Error: Makefile not found: ${MAKEFILE}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Check whether the patch is already applied
# ---------------------------------------------------------------------------
GUARD_MARKER="# Kernel 6.x compatibility: \$(src) fallback"
if grep -qF "${GUARD_MARKER}" "${MAKEFILE}"; then
    echo "Patch already applied to ${MAKEFILE} — nothing to do."
else
    echo "Applying include-path fix to ${MAKEFILE} …"

    # Create a timestamped backup
    BACKUP="${MAKEFILE}.bak.$(date +%Y%m%d%H%M%S)"
    cp "${MAKEFILE}" "${BACKUP}"
    echo "  Backup saved: ${BACKUP}"

    # The patch inserts a guard block that ensures $(src) is non-empty.
    # We insert it after the very first line of the Makefile so that it
    # takes effect before any EXTRA_CFLAGS lines are evaluated.
    python3 - "${MAKEFILE}" <<'PYEOF'
import sys

makefile_path = sys.argv[1]

guard = """\
# Kernel 6.x compatibility: $(src) fallback
# Starting with kernel 6.x, $(src) is not guaranteed to be set for
# out-of-tree module builds.  Fall back to $(M) (set by kbuild/DKMS)
# so that EXTRA_CFLAGS include paths resolve to the module source root.
ifeq ($(src),)
  src := $(M)
endif
ifeq ($(src),)
  src := $(shell pwd)
endif

"""

with open(makefile_path, "r") as fh:
    lines = fh.readlines()

# Insert after the first line
patched = [lines[0], "\n", guard] + lines[1:]

with open(makefile_path, "w") as fh:
    fh.writelines(patched)

print("  Makefile patched successfully.")
PYEOF
fi

# ---------------------------------------------------------------------------
# Rebuild the DKMS module for the target kernel
# ---------------------------------------------------------------------------
echo ""
echo "Rebuilding ${DRIVER_NAME}/${DRIVER_VERSION} for kernel ${KERNEL_VER} …"

# Remove any cached failed build artefacts first
dkms remove -m "${DRIVER_NAME}" -v "${DRIVER_VERSION}" -k "${KERNEL_VER}" \
    --no-depmod 2>/dev/null || true

dkms build  -m "${DRIVER_NAME}" -v "${DRIVER_VERSION}" -k "${KERNEL_VER}"
dkms install -m "${DRIVER_NAME}" -v "${DRIVER_VERSION}" -k "${KERNEL_VER}"

echo ""
echo "Done.  Module installed for kernel ${KERNEL_VER}."
echo "Reload with:  sudo modprobe 88XXau"
