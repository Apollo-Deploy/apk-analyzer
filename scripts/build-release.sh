#!/bin/bash
# Build release binaries for all supported platforms
# This script requires Zig to be installed on the build machine
# The resulting binaries are standalone and don't require Zig to run

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_DIR/dist"

echo "Building APK Analyzer CLI release binaries..."
echo "Project directory: $PROJECT_DIR"
echo "Output directory: $OUTPUT_DIR"

# Clean previous builds
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

cd "$PROJECT_DIR"

# Build for all platforms
echo ""
echo "Building release binaries for all platforms..."
zig build release

# Move binaries to dist folder with proper naming
echo ""
echo "Packaging binaries..."

# Linux x86_64
if [ -f "zig-out/x86_64-linux/apk-analyzer" ]; then
    mkdir -p "$OUTPUT_DIR/linux-x64"
    cp "zig-out/x86_64-linux/apk-analyzer" "$OUTPUT_DIR/linux-x64/apk-analyzer"
    chmod +x "$OUTPUT_DIR/linux-x64/apk-analyzer"
    echo "  ✓ linux-x64"
fi

# Linux ARM64
if [ -f "zig-out/aarch64-linux/apk-analyzer" ]; then
    mkdir -p "$OUTPUT_DIR/linux-arm64"
    cp "zig-out/aarch64-linux/apk-analyzer" "$OUTPUT_DIR/linux-arm64/apk-analyzer"
    chmod +x "$OUTPUT_DIR/linux-arm64/apk-analyzer"
    echo "  ✓ linux-arm64"
fi

# macOS x86_64
if [ -f "zig-out/x86_64-macos/apk-analyzer" ]; then
    mkdir -p "$OUTPUT_DIR/darwin-x64"
    cp "zig-out/x86_64-macos/apk-analyzer" "$OUTPUT_DIR/darwin-x64/apk-analyzer"
    chmod +x "$OUTPUT_DIR/darwin-x64/apk-analyzer"
    echo "  ✓ darwin-x64"
fi

# macOS ARM64 (Apple Silicon)
if [ -f "zig-out/aarch64-macos/apk-analyzer" ]; then
    mkdir -p "$OUTPUT_DIR/darwin-arm64"
    cp "zig-out/aarch64-macos/apk-analyzer" "$OUTPUT_DIR/darwin-arm64/apk-analyzer"
    chmod +x "$OUTPUT_DIR/darwin-arm64/apk-analyzer"
    echo "  ✓ darwin-arm64"
fi

# Windows x86_64
if [ -f "zig-out/x86_64-windows/apk-analyzer.exe" ]; then
    mkdir -p "$OUTPUT_DIR/win32-x64"
    cp "zig-out/x86_64-windows/apk-analyzer.exe" "$OUTPUT_DIR/win32-x64/apk-analyzer.exe"
    echo "  ✓ win32-x64"
fi

# Create archives for distribution
echo ""
echo "Creating distribution archives..."

cd "$OUTPUT_DIR"

for dir in */; do
    platform="${dir%/}"
    if [ -d "$platform" ]; then
        if [[ "$platform" == win32* ]]; then
            # Create zip for Windows
            zip -q -r "apk-analyzer-$platform.zip" "$platform"
            echo "  ✓ apk-analyzer-$platform.zip"
        else
            # Create tar.gz for Unix
            tar -czf "apk-analyzer-$platform.tar.gz" "$platform"
            echo "  ✓ apk-analyzer-$platform.tar.gz"
        fi
    fi
done

echo ""
echo "Build complete! Binaries available in: $OUTPUT_DIR"
echo ""
echo "Platform binaries:"
ls -la "$OUTPUT_DIR"
