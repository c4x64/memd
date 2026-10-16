#!/bin/sh
# DSU offline compile check — no gradle, no network.
# Compiles every .java source under app/src/main/java with javac against
# android.jar found under ~/Library/Android/sdk/platforms.
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/app/src/main/java"
OUT="$ROOT/build/classes"

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
