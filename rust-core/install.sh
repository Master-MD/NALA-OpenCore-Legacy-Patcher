#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
echo "[NALA-oclp-rs] Building 100% Pure Safe Rust release binary (-D warnings)..."
(cd "$ROOT_DIR" && RUSTFLAGS="-D warnings" cargo build --release)
mkdir -p "$HOME/bin"
cp "$ROOT_DIR/target/release/nala-oclp-rs" "$HOME/bin/nala-oclp-rs"
chmod +x "$HOME/bin/nala-oclp-rs"
ln -sf "$HOME/bin/nala-oclp-rs" "$HOME/bin/oclp-rs"
echo "[NALA-oclp-rs] Installed to $HOME/bin/nala-oclp-rs (symlink: $HOME/bin/oclp-rs)"
"$HOME/bin/nala-oclp-rs" --version
