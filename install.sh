#!/bin/bash
# Corrode Installer Script
# Installs corrode binary to /usr/local/bin for global access

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   🦀 Corrode Security Scanner         ║${NC}"
echo -e "${CYAN}║   Installation Script                 ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] This script should NOT be run as root${NC}"
   echo -e "${YELLOW}[*] It will ask for sudo when needed${NC}"
   exit 1
fi

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}[!] Cargo/Rust not found${NC}"
    echo -e "${YELLOW}[*] Install Rust from: https://rustup.rs/${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Building release binary...${NC}"
cargo build --release

if [ ! -f "target/release/corrode" ]; then
    echo -e "${RED}[!] Build failed - binary not found${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Build successful${NC}"
echo ""

# Determine installation directory
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*] Installing to $INSTALL_DIR (requires sudo)${NC}"
    sudo cp target/release/corrode "$INSTALL_DIR/corrode"
    sudo chmod +x "$INSTALL_DIR/corrode"
else
    echo -e "${CYAN}[*] Installing to $INSTALL_DIR${NC}"
    cp target/release/corrode "$INSTALL_DIR/corrode"
    chmod +x "$INSTALL_DIR/corrode"
fi

echo -e "${GREEN}[✓] Corrode installed successfully!${NC}"
echo ""
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Quick Start                         ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}1.${NC} Create a targets file:"
echo -e "   ${CYAN}cp targets.txt.example targets.txt${NC}"
echo -e "   ${CYAN}nano targets.txt${NC}  ${YELLOW}# Add your URLs${NC}"
echo ""
echo -e "${GREEN}2.${NC} Run your first scan:"
echo -e "   ${CYAN}corrode${NC}  ${YELLOW}# Uses targets.txt by default${NC}"
echo ""
echo -e "${GREEN}3.${NC} Or scan a single site:"
echo -e "   ${CYAN}corrode https://example.com${NC}"
echo ""
echo -e "${GREEN}4.${NC} View detailed help:"
echo -e "   ${CYAN}corrode --help${NC}"
echo ""
echo -e "${YELLOW}Note: Make sure /usr/local/bin is in your PATH${NC}"
echo -e "${YELLOW}Test: ${CYAN}which corrode${NC}"
echo ""
