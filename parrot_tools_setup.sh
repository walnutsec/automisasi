#!/bin/bash

# ==============================================================================
# Parrot OS Tools Installation Script for Enhanced Recon
# Run this script to install all required tools
# Usage: chmod +x install_tools.sh && ./install_tools.sh
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

echo -e "${PURPLE}"
echo "██████╗  █████╗ ██████╗ ██████╗  ██████╗ ██████╗    ███████╗███████╗████████╗██╗   ██╗██████╗ "
echo "██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗   ██╔════╝██╔════╝╚══██╔══╝██║   ██║██╔══██╗"
echo "██████╔╝███████║██████╔╝██████╔╝██║   ██║██████╔╝   ███████╗█████╗     ██║   ██║   ██║██████╔╝"
echo "██╔═══╝ ██╔══██║██╔══██╗██╔══██╗██║   ██║██╔══██╗   ╚════██║██╔══╝     ██║   ██║   ██║██╔═══╝ "
echo "██║     ██║  ██║██║  ██║██║  ██║╚██████╔╝██║  ██║   ███████║███████╗   ██║   ╚██████╔╝██║     "
echo "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝     "
echo -e "${NC}"
echo -e "${CYAN}Enhanced Recon Tools Installation for Parrot OS${NC}"
echo ""

# Check if running as root for some installations
if [[ $EUID -eq 0 ]]; then
   print_warning "Running as root. Some Go tools will be installed in /root/go/bin"
else
   print_status "Running as user. Go tools will be installed in ~/go/bin"
fi

echo ""
print_status "Starting tools installation..."
echo ""

# Update system
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y
print_success "System updated"

# Install basic dependencies
print_status "Installing basic dependencies..."
sudo apt install -y curl wget git build-essential python3 python3-pip golang-go
print_success "Basic dependencies installed"

# Check if Go is properly configured
if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

# Set Go environment if not set
if [ -z "$GOPATH" ]; then
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    print_status "Go environment configured"
fi

# Create Go directories
mkdir -p $GOPATH/bin
mkdir -p $GOPATH/src

echo ""
print_status "Installing reconnaissance tools..."
echo ""

# 1. WHATWEB (Usually pre-installed in Parrot)
print_status "Installing WhatWeb..."
if command -v whatweb &> /dev/null; then
    print_success "WhatWeb already installed"
else
    sudo apt install -y whatweb
    print_success "WhatWeb installed"
fi

# 2. NMAP (Usually pre-installed in Parrot)
print_status "Installing Nmap..."
if command -v nmap &> /dev/null; then
    print_success "Nmap already installed"
else
    sudo apt install -y nmap
    print_success "Nmap installed"
fi

# 3. SUBFINDER
print_status "Installing Subfinder..."
if command -v subfinder &> /dev/null; then
    print_success "Subfinder already installed"
else
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    print_success "Subfinder installed"
fi

# 4. HTTPX
print_status "Installing httpx..."
if command -v httpx &> /dev/null; then
    print_success "httpx already installed"
else
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    print_success "httpx installed"
fi

# 5. NUCLEI
print_status "Installing Nuclei..."
if command -v nuclei &> /dev/null; then
    print_success "Nuclei already installed"
else
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    print_success "Nuclei installed"
fi

# 6. FFUF
print_status "Installing ffuf..."
if command -v ffuf &> /dev/null; then
    print_success "ffuf already installed"
else
    go install github.com/ffuf/ffuf@latest
    print_success "ffuf installed"
fi

# 7. ASSETFINDER
print_status "Installing Assetfinder..."
if command -v assetfinder &> /dev/null; then
    print_success "Assetfinder already installed"
else
    go install github.com/tomnomnom/assetfinder@latest
    print_success "Assetfinder installed"
fi

# 8. WAYBACKURLS
print_status "Installing waybackurls..."
if command -v waybackurls &> /dev/null; then
    print_success "waybackurls already installed"
else
    go install github.com/tomnomnom/waybackurls@latest
    print_success "waybackurls installed"
fi

# 9. NIKTO
print_status "Installing Nikto..."
if command -v nikto &> /dev/null; then
    print_success "Nikto already installed"
else
    sudo apt install -y nikto
    print_success "Nikto installed"
fi

echo ""
print_status "Installing wordlists..."
echo ""

# Install SecLists
if [ ! -d "/usr/share/seclists" ]; then
    print_status "Installing SecLists wordlists..."
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
    print_success "SecLists installed"
else
    print_success "SecLists already installed"
fi

# Install additional wordlists
print_status "Installing additional wordlists..."
sudo mkdir -p /usr/share/wordlists/dirbuster
sudo mkdir -p /usr/share/wordlists/dirb

# Download directory-list if not exists
if [ ! -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]; then
    sudo wget -q https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-medium.txt -O /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    print_success "Directory-list wordlist downloaded"
fi

# Install dirb wordlists
if ! dpkg -l | grep -q "^ii.*dirb "; then
    sudo apt install -y dirb
    print_success "Dirb (with wordlists) installed"
fi

echo ""
print_status "Updating Nuclei templates..."
if command -v nuclei &> /dev/null; then
    nuclei -update-templates
    print_success "Nuclei templates updated"
fi

echo ""
print_status "Verifying installations..."
echo ""

# Verify tools
TOOLS=("whatweb" "nmap" "subfinder" "httpx" "nuclei" "ffuf" "assetfinder" "waybackurls" "nikto")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        print_success "$tool ✓"
    else
        print_error "$tool ✗"
        MISSING_TOOLS+=($tool)
    fi
done

# Check wordlists
echo ""
print_status "Checking wordlists..."
WORDLIST_FOUND=false

WORDLISTS=(
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "/usr/share/wordlists/dirb/common.txt"
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
)

for wl in "${WORDLISTS[@]}"; do
    if [ -f "$wl" ]; then
        print_success "Wordlist found: $wl"
        WORDLIST_FOUND=true
        break
    fi
done

if [ "$WORDLIST_FOUND" = false ]; then
    print_warning "No wordlists found in common locations"
fi

echo ""
echo "==============================================================================="
if [ ${#MISSING_TOOLS[@]} -eq 0 ] && [ "$WORDLIST_FOUND" = true ]; then
    print_success "🎉 All tools and wordlists installed successfully!"
    echo ""
    print_status "You may need to restart your terminal or run:"
    echo -e "${YELLOW}source ~/.bashrc${NC}"
    echo ""
    print_status "Your enhanced recon script is ready to use!"
elif [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    print_warning "Some tools failed to install: ${MISSING_TOOLS[*]}"
    echo ""
    print_status "You can manually install missing tools:"
    for tool in "${MISSING_TOOLS[@]}"; do
        case $tool in
            "subfinder"|"httpx"|"nuclei"|"ffuf"|"assetfinder"|"waybackurls")
                echo -e "${YELLOW}  go install -v github.com/projectdiscovery/$tool/cmd/$tool@latest${NC}"
                ;;
            *)
                echo -e "${YELLOW}  sudo apt install -y $tool${NC}"
                ;;
        esac
    done
else
    print_success "All tools installed! Just missing some wordlists."
fi

echo ""
print_status "Installation completed!"
echo -e "${CYAN}Happy Hacking! 🚀${NC}"