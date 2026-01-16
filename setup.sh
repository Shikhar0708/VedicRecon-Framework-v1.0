#!/bin/bash

# VedicRecon Framework - Linux Setup Utility
# Version: 1.0.0-alpha

echo "--- [ VedicRecon Setup: Linux ] ---"

# 1. Check for Root/Sudo
if [ "$EUID" -ne 0 ]; then 
  echo "[!] Please run as root or with sudo"
  exit
fi
#need to create these directories
echo "[*] Creating ouput/reports directory"
mkdir -p output reports
# 2. Update and Install System Dependencies
echo "[*] Installing system dependencies (nmap, ffuf, golang)..."
apt-get update -y && apt-get install -y \
    nmap \
    ffuf \
    golang-go \
    python3-pip \
    python3-venv \

# 3. Setup Python Virtual Environment
echo "[*] Setting up Python environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip --quiet

# Define your required modules
if [ -f "requirements.txt" ]; then
    # Read requirements.txt into an array, ignoring comments and empty lines
    REQUIRED_MODULES=($(grep -vE "^\s*#|^\s*$" requirements.txt | sed 's/[<>=].*//'))
else
    REQUIRED_MODULES=("pandas" "requests" "google-genai" "python-dotenv")
fi

echo "[*] Verifying Python modules..."
MISSING_MODULES=()

for module in "${REQUIRED_MODULES[@]}"; do
    # pip show returns 0 if found, 1 if not
    if ! pip show "$module" > /dev/null 2>&1; then
        echo "    [!] $module is missing."
        MISSING_MODULES+=("$module")
    else
        echo "    [OK] $module is present."
    fi
done

if [ ${#MISSING_MODULES[@]} -gt 0 ]; then
    echo "[*] Installing missing modules: ${MISSING_MODULES[*]}..."
    pip install "${MISSING_MODULES[@]}"
else
    echo "[+] All Python dependencies are satisfied."
fi

# 4. Compile Go Muscle
echo "[*] Compiling Go core binaries..."
mkdir -p bin
cd core
# Check if module is already initialized to avoid "already exists" error
if [ ! -f "go.mod" ]; then
    go mod init vedicrecon/core
fi
go build -o ../bin/vr_core_linux .
echo "[*] Built System Dependency Loader Successfully"
cd ..

# 5. Initialize Directory Structure
echo "[*] Creating workspace folders..."
mkdir -p output reports .runtime_integrity

# 6. Set Permissions
chmod +x bin/vr_core_linux
chmod +x main.py

echo "[+] Setup Complete. Run the tool with: sudo ./venv/bin/python3 main.py"