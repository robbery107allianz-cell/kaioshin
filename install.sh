#!/bin/bash
# MASS — One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash
#    or: git clone ... && cd mass && ./install.sh

set -uo pipefail

INSTALL_DIR="${KAIOSHIN_INSTALL_DIR:-$HOME/.kaioshin}"

echo "Kaioshin 界王神 — Mac AI Security Sandbox"
echo ""

# Check if already cloned (running from repo)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/kaioshin" ] && [ -f "$SCRIPT_DIR/configs/sandbox.sb.template" ]; then
  echo "Running from local repo: $SCRIPT_DIR"
  INSTALL_DIR="$SCRIPT_DIR"
else
  # Clone if needed
  if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing installation..."
    cd "$INSTALL_DIR" && git pull --quiet
  else
    echo "Installing to $INSTALL_DIR..."
    git clone --quiet https://github.com/rob-hn/kaioshin.git "$INSTALL_DIR"
  fi
fi

cd "$INSTALL_DIR"
chmod +x kaioshin

# Run install
./kaioshin install

echo ""
echo "Add to your PATH (optional):"
echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.zshrc"
echo ""
echo "Or create aliases:"
echo "  echo 'alias kaioshin=\"$INSTALL_DIR/kaioshin\"' >> ~/.zshrc"
echo "  echo 'alias ks=\"$INSTALL_DIR/kaioshin\"' >> ~/.zshrc"
echo "  echo 'alias claude-safe=\"$INSTALL_DIR/kaioshin launch claude\"' >> ~/.zshrc"
