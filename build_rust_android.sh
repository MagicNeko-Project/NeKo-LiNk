#!/bin/bash
set -e

# NekoLink Android Rust Build Script
# Usage: ./build_rust_android.sh

KEYBOARD_INTERRUPT=130

# Set local SDK/NDK paths
export ANDROID_HOME="$(pwd)/android-sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.1.10909125"

# Add toolchains to PATH if needed (cargo-ndk handles this usually, but good for safety)
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"

if [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "Error: NDK not found at $ANDROID_NDK_HOME"
    exit 1
fi

# Architectures to build for
ARCHS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
RUST_TARGETS=("aarch64-linux-android" "armv7-linux-androideabi" "i686-linux-android" "x86_64-linux-android")

BASE_DIR="$(pwd)"
RUST_DIR="$BASE_DIR/nekolink-android"
JNI_LIBS_DIR="$BASE_DIR/wireguard-android/tunnel/src/main/jniLibs"

echo "Building NekoLink Android Library..."
echo "Using NDK: $ANDROID_NDK_HOME"

cd "$RUST_DIR"

for i in "${!ARCHS[@]}"; do
    ARCH="${ARCHS[$i]}"
    TARGET="${RUST_TARGETS[$i]}"
    
    echo "Check/Add Target: $TARGET..."
    rustup target add "$TARGET" || true

    echo "Building for $ARCH ($TARGET)..."
    if command -v cargo-ndk &> /dev/null; then
        cargo ndk -t "$ARCH" -o "$JNI_LIBS_DIR" build --release
    else 
        echo "Error: cargo-ndk not found. Please install it with: cargo install cargo-ndk"
        exit 1
    fi
done

echo "Build complete. Libraries installed to $JNI_LIBS_DIR"
ls -R "$JNI_LIBS_DIR"
