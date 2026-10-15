#!/bin/bash
#
# Build Zipee.app and package it as Zipee-<version>-macOS.pkg.
#
# This script must run on macOS with Xcode's command line tools installed. It
# is the single source of truth for how the app is built: the CI workflow calls
# it, and so can a developer, so a local build and a CI build produce the same
# layout.
#
# Signing is opportunistic. With no credentials the script still produces a
# real, installable, explicitly unsigned package and says so loudly, because a
# package that is merely named ".pkg" is worthless. With credentials it signs,
# notarizes and staples.
#
# Usage:
#   scripts/build-macos.sh [--skip-tests] [--output-dir DIR]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml | head -1)"
BUILD_NUMBER="${ZIPEE_BUILD_NUMBER:-$(git rev-list --count HEAD 2>/dev/null || echo 1)}"
OUTPUT_DIR="$REPO_ROOT/dist"
SKIP_TESTS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-tests) SKIP_TESTS=1; shift ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight --------------------------------------------------------------

[[ "$(uname -s)" == "Darwin" ]] || die "this script builds a macOS app and must run on macOS"
command -v xcrun >/dev/null || die "xcrun not found; install the Xcode command line tools"
command -v cargo >/dev/null || die "cargo not found; install Rust from https://rustup.rs"

BUILD_DIR="$REPO_ROOT/target/macos"
APP_NAME="Zipee"
BUNDLE_ID="app.zipee.Zipee"
APP="$BUILD_DIR/$APP_NAME.app"
DEPLOYMENT_TARGET_NUMBER="${ZIPEE_DEPLOYMENT_TARGET:-14.0}"
CONTENTS="$APP/Contents"
PKG_NAME="${APP_NAME}-${VERSION}-macOS.pkg"

rm -rf "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

# --- tests ------------------------------------------------------------------

if [[ "$SKIP_TESTS" -eq 0 ]]; then
  log "Running the test suite"
  # The engine tests must pass before anything is shipped; they are the only
  # thing standing between a zip-slip bug and a release.
  (cd "$REPO_ROOT" && cargo test --workspace --locked)
else
  warn "skipping tests because --skip-tests was passed"
fi

# --- native engine ----------------------------------------------------------

# `uname -m` and Rust's target triple disagree on Apple silicon: the kernel
# reports "arm64", the toolchain wants "aarch64-apple-darwin". Getting this
# wrong makes the target look uninstalled forever.
rust_target_for_arch() {
  case "$1" in
    arm64)  echo "aarch64-apple-darwin" ;;
    x86_64) echo "x86_64-apple-darwin" ;;
    *)      echo "" ;;
  esac
}

HOST_ARCH="$(uname -m)"
HOST_TARGET="$(rust_target_for_arch "$HOST_ARCH")"
[[ -n "$HOST_TARGET" ]] || die "unsupported architecture: $HOST_ARCH"

# Build both slices so the shipped binary is universal. A runner may only be
# able to produce one; that is reported rather than hidden.
WANT_TARGETS=("$HOST_TARGET")
CROSS_TARGET="$(rust_target_for_arch "$(if [[ "$HOST_ARCH" == arm64 ]]; then echo x86_64; else echo arm64; fi)")"
[[ -n "$CROSS_TARGET" ]] && WANT_TARGETS+=("$CROSS_TARGET")

# Ask for the cross target explicitly, and say so if it is refused: a missing
# target silently produces a single-architecture app, which is worth knowing.
if ! rustup target add "${WANT_TARGETS[@]}" 2>&1 | tail -5; then
  warn "rustup could not add every target; continuing with what is installed"
fi

log "Building the archive core for: ${WANT_TARGETS[*]}"
SLICES=()
for target in "${WANT_TARGETS[@]}"; do
  if ! rustup target list --installed | grep -qx "$target"; then
    if [[ "$target" == "$HOST_TARGET" ]]; then
      die "the host Rust target $HOST_TARGET is not installed; run: rustup target add $HOST_TARGET"
    fi
    warn "  skipping $target (not installed); the app will be single-architecture"
    continue
  fi
  log "  building $target"
  # Without this the Rust objects are stamped with the runner's SDK version and
  # the linker reports them as "built for newer macOS version than being
  # linked" -- i.e. the shipped binary would call APIs the deployment target
  # does not have.
  (cd "$REPO_ROOT" && MACOSX_DEPLOYMENT_TARGET="$DEPLOYMENT_TARGET_NUMBER" \
    cargo build --release --locked -p zipee-engine --target "$target")
  slice="$REPO_ROOT/target/$target/release/libzipee_engine.a"
  [[ -f "$slice" ]] || die "expected a static library at $slice but cargo did not produce one"
  SLICES+=("$slice")
done

[[ ${#SLICES[@]} -ge 1 ]] || die "no archive core was built"

# The app can only be compiled for an architecture the core was built for.
WANT_ARCHS=()
for target in "${WANT_TARGETS[@]}"; do
  slice="$REPO_ROOT/target/$target/release/libzipee_engine.a"
  [[ -f "$slice" ]] || continue
  case "$target" in
    aarch64-apple-darwin) WANT_ARCHS+=(arm64) ;;
    x86_64-apple-darwin)  WANT_ARCHS+=(x86_64) ;;
  esac
done
[[ ${#WANT_ARCHS[@]} -ge 1 ]] || die "no usable architecture slice was built"

LIB="$BUILD_DIR/libzipee_engine.a"
# `lipo` writes a temporary next to its output and fails if the directory is
# absent, so create it rather than relying on the app-bundle step later.
mkdir -p "$BUILD_DIR"
rm -f "$LIB"
lipo -create "${SLICES[@]}" -output "$LIB"
log "archive core: $(lipo -archs "$LIB")"

# --- app bundle -------------------------------------------------------------



log "Assembling $APP_NAME.app"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources"

# Info.plist: substitute the version rather than maintaining two files.
sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD_NUMBER/" \
  "$REPO_ROOT/macos/Zipee/Resources/Info.plist" > "$CONTENTS/Info.plist"

printf 'APPL????' > "$CONTENTS/PkgInfo"

# Compile the Swift sources against the Rust header and static library.
cat > "$BUILD_DIR/ZipeeEngine.h" <<'HEADER'
#ifndef ZIPEE_ENGINE_H
#define ZIPEE_ENGINE_H
#include <stdint.h>
#include <stdlib.h>
typedef struct ZipeeArchive ZipeeArchive;
typedef struct { uint8_t *data; size_t len; size_t capacity; } ZipeeBytes;
typedef struct {
    uint64_t total_entries, files, directories, unsafe_entries;
    uint64_t encrypted_entries, uncompressed_bytes, compressed_bytes;
} ZipeeStats;
typedef struct {
    char *name; int32_t kind, is_unsafe, is_encrypted;
    uint64_t uncompressed_size, compressed_size; uint32_t unix_mode; uint64_t modified;
} ZipeeEntry;
ZipeeArchive *zipee_open(const char *path, char **error_out);
void zipee_close(ZipeeArchive *handle);
ZipeeStats zipee_stats(ZipeeArchive *handle, char **error_out);
int32_t zipee_entries(ZipeeArchive *h, ZipeeEntry *out, size_t cap, size_t *count, char **err);
ZipeeBytes zipee_read_entry(ZipeeArchive *h, const char *name, char **err);
int32_t zipee_extract(ZipeeArchive *h, const char *spec, const char *dest,
                      uint64_t max_bytes, char **report, char **err);
void zipee_bytes_free(ZipeeBytes bytes);
void zipee_string_free(char *s);
char *zipee_version(void);
#endif
HEADER

# macOS still ships bash 3.2 as /bin/bash, which has no `mapfile`.
SWIFT_SOURCES=()
while IFS= read -r line; do
  SWIFT_SOURCES+=("$line")
done < <(find "$REPO_ROOT/macos/Zipee" -name '*.swift' | sort)
[[ ${#SWIFT_SOURCES[@]} -gt 0 ]] || die "no Swift sources found under macos/Zipee"

# -warnings-as-errors is deliberate: a warning in a shipping app is a defect
# that will not be caught later, and there is no separate review step here.
APP_SLICES=()
for arch in "${WANT_ARCHS[@]}"; do
  slice_out="$BUILD_DIR/Zipee-$arch"
  log "  compiling the app for $arch"
  xcrun swiftc \
    -O \
    -target "${arch}-apple-macos${DEPLOYMENT_TARGET_NUMBER}" \
    -sdk "$(xcrun --show-sdk-path --sdk macosx)" \
    -import-objc-header "$BUILD_DIR/ZipeeEngine.h" \
    -L "$BUILD_DIR" \
    -lzipee_engine \
    -framework SwiftUI -framework AppKit -framework UniformTypeIdentifiers \
    -lz -lbz2 -liconv \
    -Xlinker -force_load -Xlinker "$LIB" \
    -Xlinker -dead_strip \
    -warnings-as-errors \
    -o "$slice_out" \
    "${SWIFT_SOURCES[@]}" || die "swiftc failed for $arch"
  [[ -f "$slice_out" ]] || die "swiftc produced no binary for $arch"
  APP_SLICES+=("$slice_out")
done

if [[ ${#APP_SLICES[@]} -gt 1 ]]; then
  lipo -create "${APP_SLICES[@]}" -output "$CONTENTS/MacOS/$APP_NAME"
else
  cp "${APP_SLICES[0]}" "$CONTENTS/MacOS/$APP_NAME"
fi

# Prove the binary exists and is a Mach-O before packaging anything. A silent
# empty executable would otherwise reach the package.
[[ -f "$CONTENTS/MacOS/$APP_NAME" ]] || die "swiftc produced no executable at $CONTENTS/MacOS/$APP_NAME"
file "$CONTENTS/MacOS/$APP_NAME" | grep -q 'Mach-O' \
  || die "the built executable is not a Mach-O: $(file -b "$CONTENTS/MacOS/$APP_NAME")"
log "executable: $(file -b "$CONTENTS/MacOS/$APP_NAME")"
# A universal binary needs every slice in one file. When only the host target
# is available the bundle is single-arch, which is fine for local use and is
# reported rather than hidden.
lipo -info "$CONTENTS/MacOS/$APP_NAME" || true

# --- signing ----------------------------------------------------------------

IDENTITY="${ZIPEE_SIGN_IDENTITY:-}"
if [[ -n "$IDENTITY" ]] && security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  log "Signing with Developer ID: $IDENTITY"
  # Inside-out: nested code must be signed before the bundle that contains it.
  codesign --force --timestamp --options runtime --sign "$IDENTITY" "$APP"
  codesign --verify --strict --verbose=2 "$APP"
  SIGNED=1
else
  warn "no signing identity available; the app and package will be UNSIGNED"
  warn "Gatekeeper will refuse to open this build without a user override"
  SIGNED=0
fi

# --- package ----------------------------------------------------------------

log "Building $PKG_NAME"

PKG_ROOT="$BUILD_DIR/pkgroot"
mkdir -p "$PKG_ROOT/Applications"
cp -R "$APP" "$PKG_ROOT/Applications/"

PKG="$OUTPUT_DIR/$PKG_NAME"

if [[ "$SIGNED" -eq 1 ]]; then
  pkgbuild \
    --root "$PKG_ROOT" \
    --identifier "$BUNDLE_ID.pkg" \
    --version "$VERSION" \
    --install-location "/" \
    --sign "$IDENTITY" \
    "$PKG" \
    || die "pkgbuild failed"
else
  pkgbuild \
    --root "$PKG_ROOT" \
    --identifier "$BUNDLE_ID.pkg" \
    --version "$VERSION" \
    --install-location "/" \
    "$PKG" \
    || die "pkgbuild failed"
fi

# --- notarization -----------------------------------------------------------

if [[ "$SIGNED" -eq 1 ]]; then
  if [[ -n "${ZIPEE_NOTARY_PROFILE:-}" ]]; then
    log "Notarizing with notarytool profile $ZIPEE_NOTARY_PROFILE"
    xcrun notarytool submit "$PKG" --keychain-profile "$ZIPEE_NOTARY_PROFILE" --wait \
      || die "notarization failed"
    xcrun stapler staple "$PKG" || die "stapling failed"
  else
    warn "ZIPEE_NOTARY_PROFILE is not set; the package is signed but NOT notarized"
  fi
fi

# --- verification and manifest ---------------------------------------------

log "Verifying the package"
# xar is the container format; this proves the artifact is a real installer
# rather than a renamed archive.
xar -tf "$PKG" >/dev/null || die "the produced file is not a valid XAR package"
pkgutil --check-signature "$PKG" >"$BUILD_DIR/signature.txt" 2>&1 || true
pkgutil --expand-full "$PKG" "$BUILD_DIR/pkg-expanded" >/dev/null \
  || die "the package will not expand"

# Where the executable lands inside the expanded tree depends on the package
# layout, so search for it rather than assuming. The point of the check is
# that the payload is really there, not that it sits at one exact path.
EXECUTABLE_FOUND="$(find "$BUILD_DIR/pkg-expanded" -type f -name "$APP_NAME" -path "*/MacOS/*" -print -quit)"
if [[ -z "$EXECUTABLE_FOUND" ]]; then
  warn "expanded package tree:"
  # `sed -n` not `head`: head closes the pipe early and, under pipefail, fails
  # the script -- which is the opposite of what a diagnostic wants.
  find "$BUILD_DIR/pkg-expanded" -maxdepth 4 | sed 's/^/    /' | sed -n '1,30p' >&2
  die "the expanded package contains no $APP_NAME executable"
fi
# The find yields the binary itself (.../Zipee.app/Contents/MacOS/Zipee), so
# the bundle's Contents directory is two levels up -- not one.
BUNDLE_CONTENTS="$(cd "$(dirname "$EXECUTABLE_FOUND")/.." && pwd)"
[[ -f "$BUNDLE_CONTENTS/Info.plist" ]] \
  || die "the executable found in the package has no Info.plist beside it"
BUNDLE_ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$BUNDLE_CONTENTS/Info.plist")"
log "payload: ${EXECUTABLE_FOUND#$BUILD_DIR/pkg-expanded/} (bundle id $BUNDLE_ID)"
pkgutil --flatten "$BUILD_DIR/pkg-expanded" "$BUILD_DIR/flattened.pkg" >/dev/null

DEPLOYMENT_TARGET="$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$CONTENTS/Info.plist")"
ARCHS="$(lipo -archs "$CONTENTS/MacOS/Zipee")"

SHA="$(shasum -a 256 "$PKG" | awk '{print $1}')"
cat > "$OUTPUT_DIR/SHA256SUMS.txt" <<MANIFEST
$SHA  $PKG_NAME
MANIFEST

cat > "$OUTPUT_DIR/release-manifest.txt" <<MANIFEST
product:            $APP_NAME
version:            $VERSION
build:              $BUILD_NUMBER
bundle id:          $BUNDLE_ID
minimum macOS:      $DEPLOYMENT_TARGET
architectures:      $ARCHS
package:            $PKG_NAME
package sha256:     $SHA
signed:             $([[ "$SIGNED" -eq 1 ]] && echo "Developer ID ($IDENTITY)" || echo "UNSIGNED")
notarized:          $([[ "$SIGNED" -eq 1 && -n "${ZIPEE_NOTARY_PROFILE:-}" ]] && echo yes || echo no)
engine version:     $(cargo run --quiet --release --bin zipee -- --version 2>/dev/null | head -1 || echo unknown)
MANIFEST

log "Done"
echo
echo "  app:       $APP"
echo "  package:   $PKG"
echo "  sha256:    $SHA"
echo "  manifest:  $OUTPUT_DIR/release-manifest.txt"
[[ "$SIGNED" -eq 1 ]] || echo
[[ "$SIGNED" -eq 1 ]] || echo "  NOTE: this package is UNSIGNED and will be blocked by Gatekeeper."
exit 0