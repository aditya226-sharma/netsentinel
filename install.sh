#!/bin/bash
#
# NetSentinel Installer
# Network Traffic Analysis & Security Monitoring Framework
#
# Supports: Kali Linux, Ubuntu, Debian
#

set -e

# ------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
INSTALL_DIR="/opt/netsentinel"
VENV_DIR="${INSTALL_DIR}/.venv"
BIN_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
    _   __     __  _____                     __
   / | / /__  / /_/ ___/____  ___  _____   / /___  __  ______
  /  |/ / _ \/ __/\__ \/ __ \/ _ \/ __ |  / / __ \/ / / / __ \
 / /|  /  __/ /_ ___/ / /_/ /  __/ /_/ / / / /_/ / /_/ / / / /
/_/ |_/\___/\__//____/ .___/\___/\__, (_)/_/\____/\__,_/_/ /_/
                    /_/          /____/

EOF
    echo -e "${NC}"
    echo -e "${BLUE}Network Traffic Analysis & Security Monitoring Framework${NC}"
    echo -e "${BLUE}Installer v1.0.0${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[!] This installer requires root privileges.${NC}"
        echo -e "${YELLOW}[*] Please run with sudo: sudo bash install.sh${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] Running as root${NC}"
}

detect_distro() {
    echo -e "${BLUE}[*] Detecting Linux distribution...${NC}"

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        DISTRO=$(echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION=$DISTRIB_RELEASE
    else
        DISTRO="unknown"
        DISTRO_VERSION="unknown"
    fi

    case $DISTRO in
        kali)
            echo -e "${GREEN}[✓] Detected: Kali Linux ${DISTRO_VERSION}${NC}"
            PKG_MANAGER="apt"
            ;;
        ubuntu|debian|linuxmint|pop)
            echo -e "${GREEN}[✓] Detected: ${DISTRO^} ${DISTRO_VERSION}${NC}"
            PKG_MANAGER="apt"
            ;;
        fedora|rhel|centos|rocky|alma)
            echo -e "${GREEN}[✓] Detected: ${DISTRO^} ${DISTRO_VERSION}${NC}"
            PKG_MANAGER="dnf"
            ;;
        arch|manjaro)
            echo -e "${GREEN}[✓] Detected: ${DISTRO^}${NC}"
            PKG_MANAGER="pacman"
            ;;
        *)
            echo -e "${YELLOW}[!] Unknown distribution: ${DISTRO}${NC}"
            echo -e "${YELLOW}[*] Attempting to use apt as package manager${NC}"
            PKG_MANAGER="apt"
            ;;
    esac
}

install_system_deps() {
    echo -e "${BLUE}[*] Installing system dependencies...${NC}"

    case $PKG_MANAGER in
        apt)
            apt-get update -qq
            apt-get install -y -qq \
                python3 \
                python3-pip \
                python3-venv \
                libpcap-dev \
                build-essential \
                python3-dev \
                libffi-dev \
                libssl-dev \
                > /dev/null 2>&1
            ;;
        dnf)
            dnf install -y -q \
                python3 \
                python3-pip \
                python3-virtualenv \
                libpcap-devel \
                gcc \
                make \
                python3-devel \
                libffi-devel \
                openssl-devel \
                > /dev/null 2>&1
            ;;
        pacman)
            pacman -Sy --noconfirm \
                python \
                python-pip \
                python-virtualenv \
                libpcap \
                base-devel \
                libffi \
                openssl \
                > /dev/null 2>&1
            ;;
    esac

    echo -e "${GREEN}[✓] System dependencies installed${NC}"
}

create_install_dir() {
    echo -e "${BLUE}[*] Creating installation directory...${NC}"

    if [[ -d "$INSTALL_DIR" ]]; then
        echo -e "${YELLOW}[!] Installation directory exists: ${INSTALL_DIR}${NC}"
        echo -e "${YELLOW}[*] Updating existing installation...${NC}"
    fi

    mkdir -p "$INSTALL_DIR"

    # Copy project files
    echo -e "${BLUE}[*] Copying project files...${NC}"
    cp -r "${SCRIPT_DIR}"/* "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "${SCRIPT_DIR}"/.[!.]* "$INSTALL_DIR/" 2>/dev/null || true

    echo -e "${GREEN}[✓] Installation directory ready: ${INSTALL_DIR}${NC}"
}

create_venv() {
    echo -e "${BLUE}[*] Creating Python virtual environment...${NC}"

    if [[ -d "$VENV_DIR" ]]; then
        rm -rf "$VENV_DIR"
    fi

    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}[✓] Virtual environment created at ${VENV_DIR}${NC}"
}

install_python_deps() {
    echo -e "${BLUE}[*] Installing Python dependencies...${NC}"

    # Activate virtual environment
    source "${VENV_DIR}/bin/activate"

    # Upgrade pip
    pip install --upgrade pip --quiet

    # Install requirements
    if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
        pip install -r "${INSTALL_DIR}/requirements.txt" --quiet
    fi

    # Install the package in development mode
    pip install -e "${INSTALL_DIR}" --quiet 2>/dev/null || true

    echo -e "${GREEN}[✓] Python dependencies installed${NC}"
}

create_executable() {
    echo -e "${BLUE}[*] Creating netsentinel executable...${NC}"

    cat > "${BIN_DIR}/netsentinel" << EXEC
#!/bin/bash
# NetSentinel launcher script
VENV_PYTHON="${VENV_DIR}/bin/python"
INSTALL_DIR="${INSTALL_DIR}"

cd "\${INSTALL_DIR}"
exec "\${VENV_PYTHON}" -m cli "\$@"
EXEC

    chmod +x "${BIN_DIR}/netsentinel"
    echo -e "${GREEN}[✓] Executable created at ${BIN_DIR}/netsentinel${NC}"
}

verify_installation() {
    echo -e "${BLUE}[*] Verifying installation...${NC}"

    source "${VENV_DIR}/bin/activate"

    # Test Python imports
    if python3 -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from config.settings import get_config
from database.db_manager import DatabaseManager
from utils.logger import setup_logger
from utils.helpers import human_readable_bytes
print('All core modules imported successfully')
" 2>/dev/null; then
        echo -e "${GREEN}[✓] Core modules verified${NC}"
    else
        echo -e "${YELLOW}[!] Some modules failed to import (non-critical)${NC}"
    fi

    # Test CLI entry point
    if python3 -c "import typer; import rich; print('CLI dependencies OK')" 2>/dev/null; then
        echo -e "${GREEN}[✓] CLI dependencies verified${NC}"
    else
        echo -e "${YELLOW}[!] CLI dependencies missing${NC}"
    fi
}

print_success() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              NetSentinel Installation Complete!             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Directory:${NC} ${INSTALL_DIR}"
    echo -e "${BLUE}Virtual Environment:${NC}   ${VENV_DIR}"
    echo -e "${BLUE}Executable:${NC}            ${BIN_DIR}/netsentinel"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  Start the server:    ${CYAN}netsentinel start${NC}"
    echo -e "  Open dashboard:      ${CYAN}netsentinel dashboard${NC}"
    echo -e "  Capture packets:     ${CYAN}netsentinel capture -i eth0${NC}"
    echo -e "  Generate report:     ${CYAN}netsentinel report -f html${NC}"
    echo -e "  List devices:        ${CYAN}netsentinel devices${NC}"
    echo -e "  Show alerts:         ${CYAN}netsentinel alerts${NC}"
    echo -e "  Show interfaces:     ${CYAN}netsentinel interfaces${NC}"
    echo -e "  Show statistics:     ${CYAN}netsentinel stats${NC}"
    echo -e "  Export data:         ${CYAN}netsentinel export -f json${NC}"
    echo -e "  Show help:           ${CYAN}netsentinel --help${NC}"
    echo ""
    echo -e "${YELLOW}Note:${NC} Packet capture requires root privileges."
    echo -e "      Use ${CYAN}sudo netsentinel start${NC} for full functionality."
    echo ""
    echo -e "${BLUE}Documentation:${NC} https://github.com/netsentinel/netsentinel"
    echo -e "${BLUE}API Docs:${NC}      http://localhost:8000/api/docs (when running)"
    echo ""
}

# ------------------------------------------------------------------
# Error handler
# ------------------------------------------------------------------

error_handler() {
    local line=$1
    local code=$2
    echo -e "${RED}[✗] Error on line ${line} (exit code: ${code})${NC}"
    echo -e "${YELLOW}[*] Installation failed. Please check the error above.${NC}"
    exit $code
}

trap 'error_handler ${LINENO} $?' ERR

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

main() {
    print_banner
    check_root
    detect_distro
    install_system_deps
    create_install_dir
    create_venv
    install_python_deps
    create_executable
    verify_installation
    print_success
}

# Run installer
main "$@"
