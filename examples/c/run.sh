#!/usr/bin/env sh
# Build the static library and link a real C program against it.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
cargo build --release
case "$(uname -s)" in
  Darwin) SYSLIBS="-framework CoreFoundation -framework Security -lc++" ;;
  *)      SYSLIBS="-lpthread -ldl -lm" ;;
esac
cc -O2 -Wall -Wextra -std=c11 \
   examples/c/demo.c \
   -I include \
   "$ROOT/target/release/libedgeguard.a" \
   $SYSLIBS \
   -o "$ROOT/target/release/edgeguard_c_demo"
exec "$ROOT/target/release/edgeguard_c_demo"
