#!/bin/bash
# Reproduce load_key_certs_crls memory leak (issue #30364) under Valgrind.
# Run from OpenSSL source root. Requires Docker.
# Usage: ./util/valgrind-leak-repro.sh [allocation_index]
#   allocation_index: which allocation to fail (default: 3500).
#   When the failed allocation lands in sk_X509_insert/sk_X509_CRL_push,
#   Valgrind will report "definitely lost" without the fix.

set -e
FAIL_AT="${1:-3500}"
SRCROOT="${2:-.}"
IMG="${OPENSSL_VALGRIND_IMAGE:-debian:bookworm-slim}"

echo "=== OpenSSL load_key_certs_crls leak reproducer under Valgrind ==="
echo "Source: $SRCROOT  Fail allocation at: $FAIL_AT  Image: $IMG"
echo ""

docker run --rm \
  -v "$SRCROOT:/src" \
  -w /src \
  "$IMG" \
  bash -ec '
    set -e
    apt-get update -qq && apt-get install -y -qq build-essential perl valgrind libssl-dev ca-certificates > /dev/null

    # Detect arch for Configure
    case "$(uname -m)" in
      x86_64)  T=linux-x86_64 ;;
      aarch64) T=linux-aarch64 ;;
      *)       T=linux-x86_64 ;;
    esac

    echo "Configuring ($T) with crypto-mdebug + allocfail-tests + no-asm ..."
    ./Configure "$T" no-shared no-asm enable-crypto-mdebug enable-allocfail-tests -O0 -g --prefix=/tmp/o > /dev/null
    echo "Building ..."
    make -j4 build_libs 2>&1 | tail -2
    make -j4 apps/openssl 2>&1 | tail -3

    echo ""
    echo "Running: openssl ts -query -cert test/certs/servercert.pem with OPENSSL_MALLOC_FAILURES=\"'"$FAIL_AT"'@0;1@100;0@0\""
    echo "Under Valgrind (--leak-check=full). Look for \"definitely lost\" in the output below."
    echo ""

    OPENSSL_MALLOC_FAILURES="'"$FAIL_AT"'@0;1@100;0@0" \
    valgrind --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite \
      --error-exitcode=99 \
      ./apps/openssl ts -query -data /dev/null -cert test/certs/servercert.pem -out /tmp/tsq.out 2>&1
  '
echo ""
echo "=== If you see \"definitely lost\" blocks (X509 or X509_CRL) above, that is the leak. ==="
echo "=== Re-apply the fix and re-run this script; the leak should disappear. ==="
