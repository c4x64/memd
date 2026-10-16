#!/bin/sh
# DSU offline compile check — no gradle, no network.
# Compiles every .java source under app/src/main/java with javac against
# android.jar found under ~/Library/Android/sdk/platforms.
#
# Usage: ./build.sh [package]
#   (no arg)  javac compile + optional NDK bridge compile (native/*.c).
#   package   all of the above, then d8 the compiled classes into
#             build/dex/classes.dex (verified with ls).
#
# NDK step: optional and non-fatal. If no usable NDK is installed it is
#   SKIPPED LOUDLY; if the bridge fails to compile the failure is reported
#   loudly but the javac gate still decides the exit code.
# APK signing / zipalign are NOT attempted here — explicit future work for
#   the Gradle/CI packaging path (see settings.gradle CI NOTE).
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/app/src/main/java"
OUT="$ROOT/build/classes"
NATIVE_SRC="$ROOT/native/memd_bridge.c"
NATIVE_OUT="$ROOT/build/native/arm64-v8a"
DEX_OUT="$ROOT/build/dex"

MODE="${1:-compile}"

ANDROID_JAR="$(ls "$HOME/Library/Android/sdk/platforms"/android-*/android.jar 2>/dev/null | sort -V | tail -n 1)"

if [ -z "${ANDROID_JAR:-}" ] || [ ! -f "$ANDROID_JAR" ]; then
  echo "ERROR: android.jar not found under ~/Library/Android/sdk/platforms" >&2
  exit 1
fi

SOURCES_COUNT="$(find "$SRC" -name '*.java' | wc -l | tr -d ' ')"
if [ -z "$SOURCES_COUNT" ] || [ "$SOURCES_COUNT" = "0" ]; then
  echo "ERROR: no java sources under $SRC" >&2
  exit 1
fi

mkdir -p "$OUT"
echo "Using android.jar: $ANDROID_JAR"
find "$SRC" -name '*.java' -exec javac -source 8 -target 8 -bootclasspath "$ANDROID_JAR" -d "$OUT" {} +
RC=$?
if [ $RC -ne 0 ]; then
  echo "COMPILE FAILED (exit $RC)" >&2
  exit $RC
fi
echo "COMPILE OK: $SOURCES_COUNT file(s) -> $OUT"

# --- Optional NDK bridge compile (arm64, min-api 26 to match minSdk) ---
# Pick the newest *usable* NDK: a version dir containing a clang toolchain.
# (A version dir may exist as an empty stub — e.g. a bare .installer dir —
# so probe for the compiler instead of trusting the directory name.)
NDK_CLANG=""
for NDK_DIR in $(ls -d "$HOME/Library/Android/sdk/ndk"/*/ 2>/dev/null | sort -V); do
  CANDIDATE="${NDK_DIR%/}/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android26-clang"
  if [ -x "$CANDIDATE" ]; then
    NDK_CLANG="$CANDIDATE"
  fi
done

if [ -z "$NDK_CLANG" ]; then
  echo "NDK SKIP: no usable NDK clang under ~/Library/Android/sdk/ndk (bridge not compiled)"
elif [ ! -f "$NATIVE_SRC" ]; then
  echo "NDK SKIP: $NATIVE_SRC not found (bridge not compiled)"
else
  echo "Using NDK clang: $NDK_CLANG"
  mkdir -p "$NATIVE_OUT"
  "$NDK_CLANG" -c -Wall -Werror -O2 "$NATIVE_SRC" -o "$NATIVE_OUT/memd_bridge.o"
  NDK_RC=$?
  if [ $NDK_RC -ne 0 ]; then
    echo "NDK BRIDGE FAILED (non-fatal, exit $NDK_RC): javac gate above is unaffected" >&2
  else
    ls -l "$NATIVE_OUT/memd_bridge.o"
    echo "NDK BRIDGE OK: $NATIVE_SRC -> $NATIVE_OUT/memd_bridge.o"
  fi
fi

# --- Optional `package` step: d8 classes -> classes.dex ---
if [ "$MODE" = "package" ]; then
  D8="$(ls -d "$HOME/Library/Android/sdk/build-tools"/*/d8 2>/dev/null | sort -V | tail -n 1)"
  if [ -z "${D8:-}" ] || [ ! -x "$D8" ]; then
    echo "ERROR: d8 not found under ~/Library/Android/sdk/build-tools" >&2
    exit 1
  fi
  echo "Using d8: $D8"
  mkdir -p "$DEX_OUT"
  find "$OUT" -name '*.class' -exec "$D8" --lib "$ANDROID_JAR" --min-api 26 --output "$DEX_OUT" {} +
  D8_RC=$?
  if [ $D8_RC -ne 0 ]; then
    echo "DEX FAILED (exit $D8_RC)" >&2
    exit $D8_RC
  fi
  ls -l "$DEX_OUT/classes.dex"
  echo "PACKAGE OK: $DEX_OUT/classes.dex (unsigned; signing/zipalign are future work)"
elif [ "$MODE" != "compile" ]; then
  echo "ERROR: unknown mode '$MODE' (usage: ./build.sh [package])" >&2
  exit 1
fi
