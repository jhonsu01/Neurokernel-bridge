#!/usr/bin/env bash
# ============================================================
# LinuxIAKernel - Setup Script
# Instala todas las dependencias y configura el entorno
# para ejecutar: sudo python3 -m execution.orchestrator.main
#
# Uso: chmod +x setup.sh && sudo ./setup.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_step()  { echo -e "\n${CYAN}[PASO]${NC} $1"; }
print_ok()    { echo -e "${GREEN}  [OK]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}  [!]${NC} $1"; }
print_error() { echo -e "${RED}  [ERROR]${NC} $1"; }

# --- Check root ---
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Este script requiere root. Ejecuta: sudo ./setup.sh${NC}"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo ""
echo "============================================================"
echo "  LinuxIAKernel - Instalador automático"
echo "  Directorio: $PROJECT_DIR"
echo "============================================================"

# --- 1. Detect distro ---
print_step "Detectando distribución..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    DISTRO_LIKE="${ID_LIKE:-$ID}"
    print_ok "Distribución: $PRETTY_NAME"
else
    print_error "No se detectó /etc/os-release"
    exit 1
fi

# --- 2. Install system packages ---
print_step "Instalando dependencias del sistema..."

install_debian() {
    apt-get update -qq
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        bpfcc-tools \
        python3-bpfcc \
        libbpfcc-dev \
        linux-headers-"$(uname -r)" \
        clang \
        llvm \
        libelf-dev \
        gcc \
        make
}

install_fedora() {
    dnf install -y \
        python3 \
        python3-pip \
        bcc \
        bcc-tools \
        python3-bcc \
        kernel-devel-"$(uname -r)" \
        kernel-headers-"$(uname -r)" \
        clang \
        llvm \
        elfutils-libelf-devel \
        gcc \
        make
}

install_arch() {
    pacman -Syu --noconfirm \
        python \
        python-pip \
        bcc \
        bcc-tools \
        python-bcc \
        linux-headers \
        clang \
        llvm \
        libelf \
        gcc \
        make
}

case "$DISTRO" in
    ubuntu|debian|linuxmint|pop)
        install_debian
        ;;
    fedora)
        install_fedora
        ;;
    centos|rhel|rocky|alma)
        # EPEL needed for BCC on RHEL-based
        dnf install -y epel-release 2>/dev/null || true
        install_fedora
        ;;
    arch|manjaro|endeavouros)
        install_arch
        ;;
    *)
        # Try debian-like if ID_LIKE contains debian/ubuntu
        if echo "$DISTRO_LIKE" | grep -qiE "debian|ubuntu"; then
            install_debian
        elif echo "$DISTRO_LIKE" | grep -qiE "fedora|rhel"; then
            install_fedora
        else
            print_error "Distribución no soportada: $DISTRO"
            echo "Instala manualmente: python3, python3-bcc, bpfcc-tools, linux-headers, clang, llvm"
            exit 1
        fi
        ;;
esac
print_ok "Paquetes del sistema instalados"

# --- 3. Verify kernel headers ---
print_step "Verificando kernel headers..."
KERNEL_VERSION="$(uname -r)"
HEADER_DIR="/lib/modules/$KERNEL_VERSION/build"
if [ -d "$HEADER_DIR" ]; then
    print_ok "Headers encontrados: $HEADER_DIR"
else
    print_warn "No se encontraron headers para kernel $KERNEL_VERSION"
    print_warn "Puede que necesites: apt install linux-headers-$KERNEL_VERSION"
fi

# --- 4. Verify kernel config (eBPF support) ---
print_step "Verificando soporte eBPF en el kernel..."
KCONFIG="/boot/config-$KERNEL_VERSION"
MISSING_CONFIG=0
if [ -f "$KCONFIG" ]; then
    for opt in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_KPROBES CONFIG_PERF_EVENTS; do
        if grep -q "^${opt}=y" "$KCONFIG" 2>/dev/null; then
            print_ok "$opt=y"
        else
            print_warn "$opt no encontrado o deshabilitado"
            MISSING_CONFIG=1
        fi
    done
else
    # Try /proc/config.gz
    if [ -f /proc/config.gz ]; then
        for opt in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_KPROBES CONFIG_PERF_EVENTS; do
            if zcat /proc/config.gz 2>/dev/null | grep -q "^${opt}=y"; then
                print_ok "$opt=y"
            else
                print_warn "$opt no encontrado"
                MISSING_CONFIG=1
            fi
        done
    else
        print_warn "No se pudo verificar config del kernel (ni $KCONFIG ni /proc/config.gz)"
    fi
fi

if [ "$MISSING_CONFIG" -eq 1 ]; then
    print_warn "Algunas opciones de kernel podrían faltar. Si el programa falla al cargar eBPF,"
    print_warn "puede que necesites un kernel con soporte BPF completo."
fi

# --- 5. Install Python dependencies system-wide (for sudo) ---
print_step "Instalando dependencias de Python..."

# When using sudo, we need packages available to root's Python.
# Install system-wide so 'sudo python3 -m ...' works.
python3 -m pip install --break-system-packages -r "$PROJECT_DIR/requirements.txt" 2>/dev/null \
    || python3 -m pip install -r "$PROJECT_DIR/requirements.txt"

print_ok "Dependencias de Python instaladas"

# --- 6. Create required directories ---
print_step "Creando directorios necesarios..."
mkdir -p "$PROJECT_DIR/logs"
mkdir -p "$PROJECT_DIR/system_memory"
mkdir -p "$PROJECT_DIR/.tmp"
mkdir -p "$PROJECT_DIR/directives"
mkdir -p "$PROJECT_DIR/execution"
print_ok "Directorios creados"

# --- 7. Setup .env ---
print_step "Configurando .env..."
if [ -f "$PROJECT_DIR/.env" ]; then
    print_ok ".env ya existe (no se sobrescribe)"
else
    if [ -f "$PROJECT_DIR/.env.example" ]; then
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
        chmod 600 "$PROJECT_DIR/.env"
        print_warn ".env creado desde .env.example"
        print_warn "EDITA .env con tu ANTHROPIC_API_KEY antes de ejecutar"
    else
        print_error "No se encontró .env ni .env.example"
    fi
fi

# --- 8. Verify BCC Python binding ---
print_step "Verificando BCC (eBPF toolkit)..."
if python3 -c "from bcc import BPF; print('BCC version:', BPF.kernel_struct_has_field)" 2>/dev/null; then
    print_ok "BCC importable desde Python"
else
    # On some distros, bcc python bindings are in a non-standard path
    BCC_PATH=$(find /usr/lib/python3* -name "bcc" -type d 2>/dev/null | head -1)
    if [ -n "$BCC_PATH" ]; then
        print_warn "BCC encontrado en: $BCC_PATH"
        print_warn "Si falla el import, agrega a PYTHONPATH:"
        PARENT_PATH=$(dirname "$BCC_PATH")
        echo "  export PYTHONPATH=$PARENT_PATH:\$PYTHONPATH"
    else
        print_error "BCC no se pudo importar. Verifica la instalación de python3-bcc"
    fi
fi

# --- 9. Verify sensor.c exists ---
print_step "Verificando sensor eBPF..."
if [ -f "$PROJECT_DIR/execution/sensor.c" ]; then
    print_ok "sensor.c encontrado"
else
    print_error "execution/sensor.c NO encontrado - el programa no podrá cargar probes"
fi

# --- 10. Quick import test ---
print_step "Verificando imports del proyecto..."
cd "$PROJECT_DIR"
if python3 -c "from execution.orchestrator.config import AppConfig; print('Config OK')" 2>/dev/null; then
    print_ok "Imports del proyecto OK"
else
    print_warn "Algunos imports fallaron - revisa los errores al ejecutar"
fi

# --- 11. Create launcher script ---
print_step "Creando script de ejecución..."
cat > "$PROJECT_DIR/run.sh" << 'LAUNCHER'
#!/usr/bin/env bash
# LinuxIAKernel - Launcher
# Uso: sudo ./run.sh

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Requiere root. Ejecuta: sudo ./run.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

exec python3 -m execution.orchestrator.main "$@"
LAUNCHER
chmod +x "$PROJECT_DIR/run.sh"
print_ok "run.sh creado (uso: sudo ./run.sh)"

# --- Summary ---
echo ""
echo "============================================================"
echo -e "  ${GREEN}Instalación completada${NC}"
echo "============================================================"
echo ""
echo "  Para ejecutar:"
echo "    cd $PROJECT_DIR"
echo "    sudo python3 -m execution.orchestrator.main"
echo ""
echo "  O con el launcher:"
echo "    sudo $PROJECT_DIR/run.sh"
echo ""
echo "  Checklist:"
echo "    [ ] Editar .env con tu ANTHROPIC_API_KEY"
echo "    [ ] (Opcional) Configurar TELEGRAM_BOT_TOKEN"
echo "    [ ] El modo por defecto es DRY-RUN (solo observa)"
echo ""
echo "============================================================"
