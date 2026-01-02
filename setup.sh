#!/bin/bash
# MWCCDC Liaison Ansible Setup Script
# Installs Ansible and required collections

set -e

echo "=== Liaison Ansible Setup ==="

# Check for Python3
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    echo "[OK] $PYTHON_VERSION found"
else
    echo "[ERROR] Python3 not found. Installing..."
    if command -v apt &>/dev/null; then
        sudo apt update && sudo apt install -y python3 python3-pip
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3 python3-pip
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3 python3-pip
    else
        echo "[ERROR] Cannot detect package manager. Please install Python3 manually."
        exit 1
    fi
fi

# Check for pip3
if ! command -v pip3 &>/dev/null; then
    echo "[WARN] pip3 not found. Installing..."
    if command -v apt &>/dev/null; then
        sudo apt install -y python3-pip
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3-pip
    fi
fi

# Install Ansible
if command -v ansible &>/dev/null; then
    ANSIBLE_VERSION=$(ansible --version | head -n1)
    echo "[OK] $ANSIBLE_VERSION found"
else
    echo "[INFO] Installing Ansible via pip..."
    pip3 install --user ansible
    
    # Add local bin to PATH if not present
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
        echo "[INFO] Added ~/.local/bin to PATH"
    fi
fi

# Verify ansible-galaxy is available
if ! command -v ansible-galaxy &>/dev/null; then
    # Try local bin path
    if [[ -x "$HOME/.local/bin/ansible-galaxy" ]]; then
        GALAXY="$HOME/.local/bin/ansible-galaxy"
    else
        echo "[ERROR] ansible-galaxy not found. Please ensure Ansible is installed."
        exit 1
    fi
else
    GALAXY="ansible-galaxy"
fi

# Install required Ansible collections
echo "[INFO] Installing Ansible collections..."
$GALAXY collection install ansible.posix community.general community.docker --force

echo ""
echo "=== Setup Complete ==="
echo "Run playbooks from this directory so ansible.cfg is picked up."
echo ""
echo "Example:"
echo "  ansible-playbook playbooks/liaison_main.yml -e tool=all"
echo ""
