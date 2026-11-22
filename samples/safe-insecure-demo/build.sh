#!/bin/sh
set -eu

if [ -z "${APKTOOL_JAR:-}" ]; then
  echo "Set APKTOOL_JAR to the absolute path of the official Apktool JAR." >&2
  exit 1
fi

sample_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_dir="$sample_dir/dist"
output_apk="$output_dir/apkinspector-safe-insecure-demo.apk"
framework_dir="$sample_dir/build/framework"

mkdir -p "$output_dir" "$framework_dir"
java -jar "$APKTOOL_JAR" build --force --frame-path "$framework_dir" "$sample_dir" --output "$output_apk"
sha256sum "$output_apk"
