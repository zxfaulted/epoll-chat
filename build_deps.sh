#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

OPENSSL_VERSION="3.5.6"
DEPS_DIR="$ROOT/.deps"
SRC_DIR="$DEPS_DIR/src"
OPENSSL_PREFIX="$DEPS_DIR/openssl"

BIN_DIR="$ROOT/bin"
BIN_LIB_DIR="$BIN_DIR/lib"
BIN_MODULES_DIR="$BIN_DIR/ossl-modules"

mkdir -p "$SRC_DIR" "$OPENSSL_PREFIX" "$BIN_LIB_DIR" "$BIN_MODULES_DIR"

cd "$SRC_DIR"

if [ ! -f "openssl-${OPENSSL_VERSION}.tar.gz" ]; then
    curl -fL -o "openssl-${OPENSSL_VERSION}.tar.gz" \
        "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
fi

if [ ! -d "openssl-${OPENSSL_VERSION}" ]; then
    tar xf "openssl-${OPENSSL_VERSION}.tar.gz"
fi

cd "$SRC_DIR/openssl-${OPENSSL_VERSION}"

if [ ! -f "$OPENSSL_PREFIX/bin/openssl" ]; then
    ./Configure linux-x86_64 \
        --prefix="$OPENSSL_PREFIX" \
        --openssldir="$OPENSSL_PREFIX/ssl" \
        shared \
        no-tests

    make -j"$(nproc)"
    make install_sw
fi

if [ -d "$OPENSSL_PREFIX/lib64" ]; then
    OPENSSL_LIBDIR="$OPENSSL_PREFIX/lib64"
else
    OPENSSL_LIBDIR="$OPENSSL_PREFIX/lib"
fi

cd "$SRC_DIR"

if [ ! -d "gost-engine" ]; then
    git clone --recursive https://github.com/gost-engine/engine.git gost-engine
fi

cd "$SRC_DIR/gost-engine"

GOST_REF="${GOST_REF:-master}"

git fetch
git checkout "$GOST_REF"
git submodule update --init --recursive

rm -rf build

cmake -S . -B build \
    -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -DOPENSSL_INCLUDE_DIR="$OPENSSL_PREFIX/include" \
    -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_LIBDIR/libcrypto.so" \
    -DOPENSSL_SSL_LIBRARY="$OPENSSL_LIBDIR/libssl.so" \
    -DCMAKE_INSTALL_PREFIX="$OPENSSL_PREFIX"

cmake --build build -j"$(nproc)"
cmake --install build

GOSTPROV="$(find "$OPENSSL_PREFIX" "$SRC_DIR/gost-engine/build" -name 'gostprov.so' | head -n 1)"

if [ -z "$GOSTPROV" ]; then
    echo "gostprov.so not found"
    exit 1
fi

cp "$GOSTPROV" "$BIN_MODULES_DIR/"

cp "$OPENSSL_LIBDIR"/libcrypto.so* "$BIN_LIB_DIR/"
cp "$OPENSSL_LIBDIR"/libssl.so* "$BIN_LIB_DIR/" 2>/dev/null || true

echo
echo "[OK] OpenSSL built into: $OPENSSL_PREFIX"
echo "[OK] libs copied to:    $BIN_LIB_DIR"
echo "[OK] provider copied to: $BIN_MODULES_DIR/gostprov.so"
echo

LD_LIBRARY_PATH="$BIN_LIB_DIR" \
OPENSSL_MODULES="$BIN_MODULES_DIR" \
"$OPENSSL_PREFIX/bin/openssl" list -providers -provider gostprov

echo
echo "Checking GOST key managers:"
LD_LIBRARY_PATH="$BIN_LIB_DIR" \
OPENSSL_MODULES="$BIN_MODULES_DIR" \
"$OPENSSL_PREFIX/bin/openssl" list -key-managers -provider default -provider gostprov | grep -i gost || {
    echo "No GOST key managers found"
    exit 1
}