#!/bin/bash
#
# setup.sh - Instalador de dependencias para Web-Recon
# Soporta Debian/Ubuntu (apt)
#

set -e

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Setup de Web-Recon ===${NC}"
echo -e "\n"

# ============================================================
# 0. Comprobación de sistema
# ============================================================
if ! command -v apt &> /dev/null; then
    echo -e "${RED}[-] Este script está pensado para Debian/Ubuntu (apt no encontrado).${NC}"
    echo -e "${RED}    Instala las dependencias manualmente si usas otra distro.${NC}"
    exit 1
fi

# ============================================================
# 1. Paquetes de sistema (apt)
# ============================================================
echo -e "${GREEN}[+] Instalando dependencias de sistema (apt)${NC}"

sudo apt update
sudo apt install -y \
    whois \
    dnsutils \
    curl \
    jq \
    whatweb \
    git \
    python3-pip \
    pipx \
    ruby-full \
    build-essential \
    golang-go

echo -e "\n"

# ============================================================
# 2. wafw00f (pip)
# ============================================================
echo -e "${GREEN}[+] Instalando wafw00f${NC}"

if command -v wafw00f &> /dev/null; then
    echo -e "${YELLOW}[!] wafw00f ya está instalado, se omite${NC}"
else
    pipx install wafw00f || pip3 install --user wafw00f
fi

echo -e "\n"

# ============================================================
# 3. wpscan (gem)
# ============================================================
echo -e "${GREEN}[+] Instalando wpscan${NC}"

if command -v wpscan &> /dev/null; then
    echo -e "${YELLOW}[!] wpscan ya está instalado, se omite${NC}"
else
    sudo gem install wpscan
fi

echo -e "\n"

# ============================================================
# 4. Herramientas Go: ffuf, subfinder, httpx
# ============================================================
echo -e "${GREEN}[+] Instalando herramientas de ProjectDiscovery / ffuf (Go)${NC}"

# Asegura que $HOME/go/bin esté en el PATH de esta sesión
export PATH="$PATH:$HOME/go/bin"

install_go_tool() {
    local nombre="$1"
    local repo="$2"

    if command -v "$nombre" &> /dev/null; then
        echo -e "${YELLOW}[!] $nombre ya está instalado, se omite${NC}"
    else
        echo -e "[*] Instalando $nombre..."
        go install "$repo@latest"
    fi
}

install_go_tool "ffuf" "github.com/ffuf/ffuf/v2"
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"

echo -e "\n"
echo -e "${YELLOW}[!] Recuerda añadir 'export PATH=\"\$PATH:\$HOME/go/bin\"' a tu ~/.bashrc o ~/.zshrc${NC}"
echo -e "${YELLOW}    si quieres usar estas herramientas fuera de este script en el futuro.${NC}"
echo -e "\n"

# ============================================================
# 5. ipinfo (script propio, incluido en el repo)
# ============================================================
echo -e "${GREEN}[+] Instalando ipinfo${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/ipinfo" ]]; then
    sudo cp "$SCRIPT_DIR/ipinfo" /usr/local/bin/ipinfo
    sudo chmod +x /usr/local/bin/ipinfo
    echo -e "[+] ipinfo copiado a /usr/local/bin/ipinfo"
else
    echo -e "${RED}[-] No se encontró 'ipinfo' junto a este script (esperado en: $SCRIPT_DIR/ipinfo)${NC}"
    echo -e "${RED}    Colócalo ahí y vuelve a ejecutar setup.sh, o cópialo manualmente a /usr/local/bin/${NC}"
fi

echo -e "\n"

# ============================================================
# 6. Wordlist: SecLists
# ============================================================
echo -e "${GREEN}[+] Comprobando SecLists (wordlist big.txt)${NC}"

SECLISTS_PATHS=("/usr/share/seclists" "/usr/bin/seclists")
BIG_TXT=""

for path in "${SECLISTS_PATHS[@]}"; do
    if [[ -f "$path/Discovery/Web-Content/big.txt" ]]; then
        BIG_TXT="$path/Discovery/Web-Content/big.txt"
        break
    fi
done

if [[ -n "$BIG_TXT" ]]; then
    echo -e "[+] SecLists ya encontrado en: $BIG_TXT"
else
    echo -e "${YELLOW}[!] SecLists no encontrado, clonando en /usr/share/seclists (puede tardar)${NC}"
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
    BIG_TXT="/usr/share/seclists/Discovery/Web-Content/big.txt"
fi

if [[ -f "$BIG_TXT" ]]; then
    echo -e "${GREEN}[+] Wordlist lista en: $BIG_TXT${NC}"
    echo -e "${YELLOW}[!] Verifica que web_recon.sh apunte a esta ruta exacta${NC}"
else
    echo -e "${RED}[-] No se pudo confirmar la wordlist tras la instalación, revisa manualmente${NC}"
fi

echo -e "\n"

# ============================================================
# 7. Resumen final
# ============================================================
echo -e "${GREEN}=== Resumen ===${NC}"

for cmd in whois dig curl jq whatweb wafw00f wpscan ffuf subfinder httpx ipinfo; do
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}[OK]${NC}  $cmd"
    else
        echo -e "${RED}[FALTA]${NC} $cmd"
    fi
done

echo -e "\n${GREEN}[+] Setup finalizado.${NC}"
echo -e "${YELLOW}[!] Abre una nueva terminal (o haz 'source ~/.bashrc') para asegurar que el PATH se actualiza.${NC}"
