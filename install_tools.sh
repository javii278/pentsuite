#!/bin/bash
# ============================================================
#  PentestSuite — Tool Installer
#  Compatible con: Kali Linux 2024+ / Ubuntu 24 LTS
#  Uso: sudo bash install_tools.sh
# ============================================================
# NO usar set -e — los fallos individuales no deben cortar todo

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }
skip()  { echo -e "    ${YELLOW}↷${NC}  $* (ya instalado)"; }

[[ "$EUID" -ne 0 ]] && { err "Ejecutar como root: sudo bash $0"; exit 1; }

TOOLS_DIR="/opt/tools"
WORDLISTS_DIR="/usr/share/wordlists"
GOROOT_DIR="/usr/local/go"
GOPATH_DIR="/root/go"
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
mkdir -p "$TOOLS_DIR/privesc" "$WORDLISTS_DIR"

export GOPATH="$GOPATH_DIR"
export PATH="$PATH:${GOROOT_DIR}/bin:${GOPATH_DIR}/bin:/root/.local/bin"

latest_release() {
    curl -s "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | cut -d'"' -f4
}

# ──────────────────────────────────────────────────────────────
#  1. APT PACKAGES
# ──────────────────────────────────────────────────────────────
info "Actualizando repositorios APT..."
apt-get update -qq 2>/dev/null || warn "apt-get update falló"

apt_install() {
    local pkg="$1"
    if dpkg -s "$pkg" &>/dev/null 2>&1; then skip "$pkg"; return 0; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkg" >/dev/null 2>&1 \
        && ok "$pkg" || warn "$pkg — no disponible en apt, se omite"
}

info "Instalando paquetes APT..."

# Core
for pkg in nmap whois dnsutils curl wget git jq unzip; do
    apt_install "$pkg"
done

# Python + build
for pkg in python3-pip python3-venv python3-dev python3-full pipx \
           build-essential libssl-dev libffi-dev libpcap-dev; do
    apt_install "$pkg"
done

# Red / protocolos
for pkg in smbclient samba-common-bin ldap-utils snmp snmp-mibs-downloader \
           ftp traceroute iputils-ping netcat-traditional netcat-openbsd \
           socat openssh-client sshuttle net-tools iproute2 tcpdump \
           masscan arp-scan netdiscover; do
    apt_install "$pkg"
done

# Ruby
for pkg in ruby ruby-dev ruby-rubygems; do
    apt_install "$pkg"
done

# Seguridad — apt
for pkg in hydra hashcat john nikto sqlmap gobuster \
           apt-transport-https ca-certificates gnupg lsb-release \
           onesixtyone sslscan cewl crunch \
           dnsenum dnsrecon fierce \
           wordlists wkhtmltopdf rlwrap; do
    apt_install "$pkg"
done

# xfreerdp (paquete diferente según distro)
if ! command -v xfreerdp &>/dev/null; then
    apt_install freerdp2-x11 || apt_install freerdp3-x11 || apt_install freerdp || true
fi

# Kali-specific (silencioso si no es Kali)
for pkg in exploitdb wfuzz whatweb feroxbuster netexec crackmapexec smbmap \
           wpscan metasploit-framework; do
    apt_install "$pkg"
done

# rockyou
if [ -f "$WORDLISTS_DIR/rockyou.txt.gz" ]; then
    gunzip -f "$WORDLISTS_DIR/rockyou.txt.gz" 2>/dev/null && ok "rockyou.txt descomprimido" || true
fi

ok "Sección APT completada"

# ──────────────────────────────────────────────────────────────
#  2. GO — versión reciente si la de apt es muy antigua
# ──────────────────────────────────────────────────────────────
GO_MIN="1.21"
GO_CURRENT=$(go version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)

go_need_update() {
    [ -z "$GO_CURRENT" ] && return 0
    python3 -c "
import sys
v = sys.argv[1:]
exit(0 if tuple(map(int,v[0].split('.'))) >= tuple(map(int,v[1].split('.'))) else 1)
" "$GO_CURRENT" "$GO_MIN" 2>/dev/null && return 1 || return 0
}

if go_need_update; then
    info "Instalando Go 1.22 desde go.dev..."
    GO_VER="1.22.4"
    curl -sL "https://go.dev/dl/go${GO_VER}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz \
        && rm -rf /usr/local/go \
        && tar -C /usr/local -xzf /tmp/go.tar.gz \
        && ok "Go ${GO_VER} instalado" || warn "Go — error descargando, usando versión de apt"
    export PATH="$PATH:/usr/local/go/bin"
else
    skip "Go ($GO_CURRENT >= $GO_MIN)"
fi

# ──────────────────────────────────────────────────────────────
#  3. PYTHON TOOLS (pipx + fallback pip)
# ──────────────────────────────────────────────────────────────
info "Instalando herramientas Python..."

if ! command -v pipx &>/dev/null; then
    pip3 install --break-system-packages pipx 2>/dev/null && ok "pipx (pip)" || warn "pipx no disponible"
fi
pipx ensurepath 2>/dev/null || true

install_pipx() {
    local pkg="$1" name="${2:-$1}"
    if command -v "$name" &>/dev/null; then skip "$name"; return 0; fi
    pipx install "$pkg" 2>/dev/null && ok "$name (pipx)" && return 0
    pip3 install --break-system-packages "$pkg" 2>/dev/null && ok "$name (pip)" && return 0
    warn "$name — error de instalación"
    return 1
}

# Impacket — suite completa de ataques Windows/AD
install_pipx impacket impacket-secretsdump

# BloodHound Python ingestor
install_pipx "git+https://github.com/dirkjanm/BloodHound.py" bloodhound-python

# OSINT
install_pipx theHarvester theHarvester

# Web / red
install_pipx netexec netexec
install_pipx wafw00f wafw00f
install_pipx dnsrecon dnsrecon
install_pipx droopescan droopescan      # CMS scanner: Drupal, Joomla, Silverstripe

# AD
install_pipx enum4linux-ng enum4linux-ng
install_pipx certipy-ad certipy
install_pipx ldapdomaindump ldapdomaindump

# Post-exploit / misc
install_pipx weasyprint weasyprint      # PDF reports
install_pipx ssh-audit ssh-audit        # SSH configuration auditor

# Responder (LLMNR/NBT-NS/mDNS poisoner)
if ! command -v responder &>/dev/null && ! command -v Responder.py &>/dev/null; then
    pip3 install --break-system-packages "git+https://github.com/lgandx/Responder" 2>/dev/null \
        && ok "responder (pip)" \
        || warn "responder — instalar desde https://github.com/lgandx/Responder"
fi

# AutoRecon
pipx install "git+https://github.com/Tib3rius/AutoRecon" 2>/dev/null && ok "autorecon" || true

# gvm-tools — CLI para Greenbone/OpenVAS (provee gvm-cli)
install_pipx gvm-tools gvm-cli

# Symlinks impacket
for script in secretsdump GetNPUsers GetUserSPNs GetTGT smbexec wmiexec psexec \
              atexec lookupsid samrdump ntlmrelayx; do
    cmd="impacket-${script,,}"
    if ! command -v "$cmd" &>/dev/null; then
        src=$(find /root/.local/bin /usr/local/bin -name "impacket-${script}" 2>/dev/null | head -1)
        [ -n "$src" ] && ln -sf "$src" "/usr/local/bin/$cmd" 2>/dev/null || true
    fi
done

ok "Herramientas Python completadas"

# ──────────────────────────────────────────────────────────────
#  4. RUBY GEMS
# ──────────────────────────────────────────────────────────────
info "Instalando Ruby gems..."

if command -v gem &>/dev/null; then
    for gem_pkg in evil-winrm wpscan; do
        if ! command -v "$gem_pkg" &>/dev/null; then
            gem install "$gem_pkg" --no-document 2>/dev/null && ok "$gem_pkg" || warn "$gem_pkg — error gem"
        else
            skip "$gem_pkg"
        fi
    done
else
    warn "Ruby/gem no disponible — evil-winrm y wpscan omitidos"
fi

# ──────────────────────────────────────────────────────────────
#  5. GO TOOLS
# ──────────────────────────────────────────────────────────────
if command -v go &>/dev/null; then
    info "Instalando herramientas Go (ProjectDiscovery + otros)..."

    install_go() {
        local pkg="$1" bin="$2"
        if command -v "$bin" &>/dev/null; then skip "$bin"; return 0; fi
        go install "$pkg" 2>/dev/null \
            && (ln -sf "${GOPATH_DIR}/bin/${bin}" "/usr/local/bin/${bin}" 2>/dev/null || true) \
            && ok "$bin" || warn "$bin — error (go install)"
    }

    # ProjectDiscovery suite
    install_go "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"   subfinder
    install_go "github.com/projectdiscovery/httpx/cmd/httpx@latest"              httpx
    install_go "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"         nuclei
    install_go "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                dnsx
    install_go "github.com/projectdiscovery/katana/cmd/katana@latest"            katana   # web crawler
    install_go "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"           naabu    # port scanner rápido

    # Web content discovery
    install_go "github.com/ffuf/ffuf/v2@latest"                                  ffuf

    # Web crawling / recon
    install_go "github.com/hakluke/hakrawler@latest"                             hakrawler
    install_go "github.com/lc/gau/v2/cmd/gau@latest"                            gau      # GetAllURLs
    install_go "github.com/tomnomnom/waybackurls@latest"                         waybackurls

    # Misc
    install_go "github.com/tomnomnom/anew@latest"                                anew
    install_go "github.com/tomnomnom/httprobe@latest"                            httprobe

    # AMASS — puede fallar con go install, fallback a binario
    if ! command -v amass &>/dev/null; then
        go install "github.com/owasp-amass/amass/v4/...@master" 2>/dev/null \
            && ln -sf "${GOPATH_DIR}/bin/amass" /usr/local/bin/amass 2>/dev/null \
            && ok "amass" \
            || warn "amass — usar binario de https://github.com/owasp-amass/amass/releases"
    else
        skip "amass"
    fi

    # Actualizar templates de Nuclei
    if command -v nuclei &>/dev/null; then
        info "Actualizando templates de Nuclei..."
        nuclei -update-templates 2>/dev/null && ok "nuclei templates actualizados" || warn "nuclei templates — error de actualización"
    fi

    ok "Herramientas Go completadas"
else
    warn "Go no disponible — saltando herramientas Go"
fi

# ──────────────────────────────────────────────────────────────
#  6. BINARIOS DESDE GITHUB RELEASES
# ──────────────────────────────────────────────────────────────
info "Descargando binarios desde GitHub releases..."

dl_bin() {
    local url="$1" dest="$2"
    curl -sL --connect-timeout 20 --retry 2 "$url" -o "$dest" 2>/dev/null \
        && chmod +x "$dest" && return 0
    return 1
}

# feroxbuster — web fuzzer rápido en Rust
if ! command -v feroxbuster &>/dev/null; then
    VER=$(latest_release "epi052/feroxbuster"); VER="${VER:-v2.10.4}"
    dl_bin "https://github.com/epi052/feroxbuster/releases/download/${VER}/feroxbuster-linux-${ARCH}.tar.gz" /tmp/ferox.tar.gz \
        && tar -xzf /tmp/ferox.tar.gz -C /tmp feroxbuster 2>/dev/null \
        && mv /tmp/feroxbuster /usr/local/bin/feroxbuster \
        && ok "feroxbuster ${VER}" || warn "feroxbuster — error descargando"
else
    skip "feroxbuster"
fi

# kerbrute — Kerberos brute / user enum
if ! command -v kerbrute &>/dev/null; then
    VER=$(latest_release "ropnop/kerbrute"); VER="${VER:-v1.0.3}"
    dl_bin "https://github.com/ropnop/kerbrute/releases/download/${VER}/kerbrute_linux_${ARCH}" /usr/local/bin/kerbrute \
        && ok "kerbrute ${VER}" || warn "kerbrute — error descargando"
else
    skip "kerbrute"
fi

# chisel — TCP/UDP tunnel via HTTP
if ! command -v chisel &>/dev/null; then
    VER=$(latest_release "jpillora/chisel"); VER="${VER:-v1.9.1}"
    VER_CLEAN="${VER#v}"
    dl_bin "https://github.com/jpillora/chisel/releases/download/${VER}/chisel_${VER_CLEAN}_linux_${ARCH}.gz" /tmp/chisel.gz \
        && gunzip -f /tmp/chisel.gz \
        && mv /tmp/chisel /usr/local/bin/chisel \
        && chmod +x /usr/local/bin/chisel \
        && ok "chisel ${VER}" || warn "chisel — error descargando"
else
    skip "chisel"
fi

# ligolo-ng proxy + agent — pivoting moderno (tun interface)
for LIGOLO_BIN in proxy agent; do
    BIN_NAME="ligolo-${LIGOLO_BIN}"
    if ! command -v "$BIN_NAME" &>/dev/null; then
        VER=$(latest_release "nicocha30/ligolo-ng"); VER="${VER:-v0.6.2}"
        VER_CLEAN="${VER#v}"
        FILE="ligolo-ng_${LIGOLO_BIN}_${VER_CLEAN}_linux_${ARCH}.tar.gz"
        dl_bin "https://github.com/nicocha30/ligolo-ng/releases/download/${VER}/${FILE}" "/tmp/ligolo_${LIGOLO_BIN}.tar.gz" \
            && tar -xzf "/tmp/ligolo_${LIGOLO_BIN}.tar.gz" -C /tmp 2>/dev/null \
            && (mv "/tmp/${LIGOLO_BIN}" "/usr/local/bin/${BIN_NAME}" 2>/dev/null \
                || find /tmp -maxdepth 2 -name "${LIGOLO_BIN}" -type f -exec mv {} "/usr/local/bin/${BIN_NAME}" \; 2>/dev/null) \
            && chmod +x "/usr/local/bin/${BIN_NAME}" \
            && ok "${BIN_NAME} ${VER}" || warn "${BIN_NAME} — error descargando"
    else
        skip "$BIN_NAME"
    fi
done

# gowitness — screenshot de URLs
if ! command -v gowitness &>/dev/null; then
    VER=$(latest_release "sensepost/gowitness"); VER="${VER:-3.0.5}"
    dl_bin "https://github.com/sensepost/gowitness/releases/download/${VER}/gowitness-linux-${ARCH}" /usr/local/bin/gowitness \
        && ok "gowitness ${VER}" || warn "gowitness — error descargando"
else
    skip "gowitness"
fi

# testssl.sh — análisis SSL/TLS completo
if [ ! -x "/usr/local/bin/testssl.sh" ]; then
    VER=$(latest_release "drwetter/testssl.sh"); VER="${VER:-v3.2}"
    curl -sL "https://github.com/drwetter/testssl.sh/releases/download/${VER}/testssl.sh-${VER}.tar.gz" -o /tmp/testssl.tar.gz 2>/dev/null \
        && tar -xzf /tmp/testssl.tar.gz -C /tmp 2>/dev/null \
        && find /tmp -name "testssl.sh" -type f | head -1 | xargs -I{} cp {} /usr/local/bin/testssl.sh \
        && chmod +x /usr/local/bin/testssl.sh \
        && ok "testssl.sh ${VER}" \
        || (curl -sL "https://raw.githubusercontent.com/drwetter/testssl.sh/3.2/testssl.sh" -o /usr/local/bin/testssl.sh 2>/dev/null \
            && chmod +x /usr/local/bin/testssl.sh && ok "testssl.sh (raw)" \
            || warn "testssl.sh — error descargando")
else
    skip "testssl.sh"
fi

# pspy64 — monitor de procesos sin privilegios
if [ ! -f "$TOOLS_DIR/privesc/pspy64" ]; then
    dl_bin "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" "$TOOLS_DIR/privesc/pspy64" \
        && ok "pspy64" || warn "pspy64 — error descargando"
else
    skip "pspy64"
fi

# linpeas
if [ ! -f "$TOOLS_DIR/privesc/linpeas.sh" ]; then
    dl_bin "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" "$TOOLS_DIR/privesc/linpeas.sh" \
        && ok "linpeas.sh" || warn "linpeas.sh — error descargando"
else
    skip "linpeas.sh"
fi

# winpeas x64
if [ ! -f "$TOOLS_DIR/privesc/winPEASx64.exe" ]; then
    dl_bin "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" "$TOOLS_DIR/privesc/winPEASx64.exe" \
        && ok "winPEASx64.exe" || warn "winPEASx64.exe — error descargando"
else
    skip "winPEASx64.exe"
fi

# winpeas x86
if [ ! -f "$TOOLS_DIR/privesc/winPEASx86.exe" ]; then
    dl_bin "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe" "$TOOLS_DIR/privesc/winPEASx86.exe" \
        && ok "winPEASx86.exe" || warn "winPEASx86.exe — error descargando"
else
    skip "winPEASx86.exe"
fi

ok "Binarios de GitHub completados"

# ──────────────────────────────────────────────────────────────
#  7. METASPLOIT FRAMEWORK (si no está instalado via apt)
# ──────────────────────────────────────────────────────────────
if ! command -v msfconsole &>/dev/null; then
    info "Instalando Metasploit Framework (puede tardar varios minutos)..."
    curl -sL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
        -o /tmp/msfinstall 2>/dev/null \
        && chmod +x /tmp/msfinstall \
        && /tmp/msfinstall \
        && ok "Metasploit instalado" \
        || warn "Metasploit — instalar manualmente: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
else
    skip "Metasploit"
fi

# ──────────────────────────────────────────────────────────────
#  8. WORDLISTS
# ──────────────────────────────────────────────────────────────
info "Instalando wordlists..."

# SecLists
if [ ! -d "$WORDLISTS_DIR/SecLists" ]; then
    info "Descargando SecLists (~900MB)..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLISTS_DIR/SecLists" 2>/dev/null \
        && ok "SecLists en $WORDLISTS_DIR/SecLists" \
        || warn "SecLists — error (comprobar conexión)"
else
    skip "SecLists"
fi

# rockyou desde SecLists si no existe
if [ ! -f "$WORDLISTS_DIR/rockyou.txt" ]; then
    for candidate in \
        "$WORDLISTS_DIR/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz" \
        "$WORDLISTS_DIR/SecLists/Passwords/Leaked-Databases/rockyou.txt"; do
        if [ -f "$candidate" ]; then
            case "$candidate" in
                *.tar.gz) tar -xzf "$candidate" -C "$WORDLISTS_DIR/" 2>/dev/null && ok "rockyou.txt extraído" ;;
                *)        cp "$candidate" "$WORDLISTS_DIR/rockyou.txt" && ok "rockyou.txt copiado" ;;
            esac
            break
        fi
    done
fi
[ -f "$WORDLISTS_DIR/rockyou.txt" ] && ok "rockyou.txt disponible" || warn "rockyou.txt no encontrado"

# Symlinks de compatibilidad (rutas que usan los comandos en los YAMLs)
mkdir -p "$WORDLISTS_DIR/dirbuster" "$WORDLISTS_DIR/dirb"
[ -f "$WORDLISTS_DIR/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" ] && \
    ln -sf "$WORDLISTS_DIR/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
           "$WORDLISTS_DIR/dirbuster/directory-list-2.3-medium.txt" 2>/dev/null || true
[ -f "$WORDLISTS_DIR/SecLists/Discovery/Web-Content/common.txt" ] && \
    ln -sf "$WORDLISTS_DIR/SecLists/Discovery/Web-Content/common.txt" \
           "$WORDLISTS_DIR/dirb/common.txt" 2>/dev/null || true

ok "Wordlists completadas"

# ──────────────────────────────────────────────────────────────
#  9. CONFIGURACIÓN FINAL
# ──────────────────────────────────────────────────────────────
info "Aplicando configuración final..."

# SNMP: desactivar MIBs para evitar warnings en snmpwalk
sed -i 's/^mibs :/#mibs :/' /etc/snmp/snmp.conf 2>/dev/null || true

# Symlink /usr/share/seclists → SecLists (rutas esperadas por herramientas)
if [ -d "$WORDLISTS_DIR/SecLists" ] && [ ! -e "/usr/share/seclists" ]; then
    ln -sf "$WORDLISTS_DIR/SecLists" /usr/share/seclists && ok "Symlink /usr/share/seclists creado"
fi

# Symlink winPEASx64.exe a /opt/ para que el módulo Impacket lo encuentre directamente
[ -f "$TOOLS_DIR/privesc/winPEASx64.exe" ] && \
    ln -sf "$TOOLS_DIR/privesc/winPEASx64.exe" /opt/winPEASx64.exe 2>/dev/null || true

# crackmapexec alias → nxc (Ubuntu 24 / nuevas versiones solo traen netexec)
if ! command -v crackmapexec &>/dev/null; then
    NXC_PATH=$(command -v nxc 2>/dev/null || command -v netexec 2>/dev/null || true)
    if [ -n "$NXC_PATH" ]; then
        ln -sf "$NXC_PATH" /usr/local/bin/crackmapexec && ok "crackmapexec → alias de nxc"
    fi
fi

# PATH permanente
add_path_line() {
    local rc="$1"
    [ -f "$rc" ] || return
    grep -qxF 'export PATH="$PATH:/root/.local/bin:/usr/local/go/bin:/root/go/bin"' "$rc" || \
        echo 'export PATH="$PATH:/root/.local/bin:/usr/local/go/bin:/root/go/bin"' >> "$rc"
}
add_path_line /root/.bashrc
[ -n "$SUDO_USER" ] && add_path_line "/home/$SUDO_USER/.bashrc" || true

chmod -R 755 "$TOOLS_DIR" 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
#  10. FLASK APP — entorno virtual Python
# ──────────────────────────────────────────────────────────────
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SUITE_DIR/requirements.txt" ]; then
    info "Instalando dependencias Python de la suite..."
    if [ ! -d "$SUITE_DIR/venv" ]; then
        python3 -m venv "$SUITE_DIR/venv" 2>/dev/null && ok "venv creado"
    fi
    "$SUITE_DIR/venv/bin/pip" install -q -r "$SUITE_DIR/requirements.txt" 2>/dev/null \
        && ok "requirements.txt instalado en venv" \
        || warn "Error instalando requirements.txt"
fi

# ──────────────────────────────────────────────────────────────
#  11. GREENBONE / OPENVAS (instrucciones)
# ──────────────────────────────────────────────────────────────
info "Nota Greenbone/OpenVAS..."
if command -v gvm-cli &>/dev/null; then
    ok "gvm-cli disponible — Greenbone integration lista"
    echo "    Para arrancar OpenVAS en Kali: sudo gvm-start"
    echo "    Usuario por defecto: admin / (contraseña generada en primer setup)"
    echo "    Ver contraseña: sudo cat /etc/gvm/pwfile 2>/dev/null || sudo gvm-check-setup"
else
    warn "gvm-cli no instalado — la integración con Greenbone no funcionará"
    echo "    En Kali:   sudo apt install gvm && sudo gvm-setup && sudo gvm-start"
    echo "    En Ubuntu: instalar Greenbone Community Edition desde https://greenbone.github.io/docs/latest/"
fi

# ──────────────────────────────────────────────────────────────
#  12. RESUMEN FINAL
# ──────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  VERIFICACIÓN DE INSTALACIÓN — PentestSuite"
echo "════════════════════════════════════════════════════════"

chk() {
    local name="$1" cmd="${2:-$1}" file="${3:-}"
    if command -v "$cmd" &>/dev/null; then
        printf "  ${GREEN}✓${NC}  %-26s %s\n" "$name" "$(command -v $cmd)"
    elif [ -n "$file" ] && [ -f "$file" ]; then
        printf "  ${GREEN}✓${NC}  %-26s %s\n" "$name" "$file"
    else
        printf "  ${RED}✗${NC}  %-26s MISSING\n" "$name"
    fi
}

echo ""
echo "── Recon / Enum ─────────────────────────────────────────"
chk "nmap"
chk "masscan"
chk "arp-scan" arp-scan
chk "netdiscover"
chk "gobuster"
chk "ffuf"
chk "feroxbuster"
chk "subfinder"
chk "httpx"
chk "nuclei"
chk "amass"
chk "dnsx"
chk "theHarvester" theHarvester
chk "whatweb" whatweb
chk "wafw00f"
chk "nikto"
chk "sslscan"
chk "testssl.sh" testssl.sh
chk "enum4linux-ng" enum4linux-ng
chk "dnsrecon"
chk "dnsenum"
chk "fierce"
chk "autorecon" autorecon

echo ""
echo "── Web Attacks ───────────────────────────────────────────"
chk "sqlmap"
chk "hakrawler"
chk "gau"
chk "waybackurls"
chk "katana"
chk "naabu"
chk "wpscan"
chk "droopescan"
chk "gowitness"
chk "searchsploit" searchsploit
chk "wkhtmltopdf"

echo ""
echo "── SMB / AD ──────────────────────────────────────────────"
chk "smbclient"
chk "smbmap"
chk "netexec"
chk "crackmapexec"
chk "impacket-secretsdump"
chk "bloodhound-python" bloodhound-python
chk "kerbrute"
chk "certipy" certipy
chk "ldapdomaindump"
chk "evil-winrm" evil-winrm
chk "responder" responder
chk "xfreerdp"

echo ""
echo "── Password / Hashes ────────────────────────────────────"
chk "hydra"
chk "hashcat"
chk "john"
chk "crunch"
chk "cewl"
chk "onesixtyone"

echo ""
echo "── C2 / Pivoting ────────────────────────────────────────"
chk "msfconsole"
chk "chisel"
chk "ligolo-proxy" ligolo-proxy
chk "ligolo-agent" ligolo-agent
chk "socat"
chk "rlwrap"
chk "sshuttle"

echo ""
echo "── Greenbone ────────────────────────────────────────────"
chk "gvm-cli"
chk "ssh-audit" ssh-audit

echo ""
echo "── PrivEsc ──────────────────────────────────────────────"
chk "linpeas.sh"    linpeas.sh    "$TOOLS_DIR/privesc/linpeas.sh"
chk "pspy64"        pspy64        "$TOOLS_DIR/privesc/pspy64"
chk "winPEASx64"   winPEASx64    "$TOOLS_DIR/privesc/winPEASx64.exe"
chk "winPEASx86"   winPEASx86    "$TOOLS_DIR/privesc/winPEASx86.exe"

echo ""
echo "── Wordlists ────────────────────────────────────────────"
[ -d "/usr/share/wordlists/SecLists" ] && \
    printf "  ${GREEN}✓${NC}  %-26s %s\n" "SecLists" "/usr/share/wordlists/SecLists" || \
    printf "  ${RED}✗${NC}  %-26s MISSING\n" "SecLists"
[ -f "/usr/share/wordlists/rockyou.txt" ] && \
    printf "  ${GREEN}✓${NC}  %-26s %s\n" "rockyou.txt" "/usr/share/wordlists/rockyou.txt" || \
    printf "  ${RED}✗${NC}  %-26s MISSING\n" "rockyou.txt"
[ -d "/usr/share/seclists" ] && \
    printf "  ${GREEN}✓${NC}  %-26s %s\n" "symlink /usr/share/seclists" "→ SecLists" || \
    printf "  ${RED}✗${NC}  %-26s MISSING\n" "/usr/share/seclists"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Para arrancar la suite: bash run.sh"
echo "  Para Greenbone en Kali: sudo gvm-start"
echo "  PATH activado en: source ~/.bashrc"
echo "  Privesc tools en: $TOOLS_DIR/privesc/"
echo "════════════════════════════════════════════════════════"
echo ""
