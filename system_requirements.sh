#!/bin/bash
# system_requirements.sh - Install system dependencies for jsosint

echo "Installing system dependencies for jsosint..."

# Detect OS
if [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
    # Debian/Ubuntu/Kali
    echo "Detected Debian-based system (Ubuntu/Kali)"
    sudo apt update
    sudo apt install -y \
        build-essential \
        python3-dev \
        python3-pip \
        python3-venv \
        libssl-dev \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        libncurses5-dev \
        libreadline-dev \
        libsqlite3-dev \
        libjpeg-dev \
        libtiff-dev \
        libfreetype6-dev \
        chromium \
        chromium-driver

elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
    # RHEL/CentOS/Fedora
    echo "Detected RHEL-based system"
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y \
        python3-devel \
        openssl-devel \
        libffi-devel \
        libxml2-devel \
        libxslt-devel \
        zlib-devel \
        ncurses-devel \
        readline-devel \
        sqlite-devel

elif [ "$(uname)" == "Darwin" ]; then
    # macOS
    echo "Detected macOS"
    brew update
    brew install \
        openssl \
        readline \
        sqlite3 \
        xz \
        zlib \
        libxml2 \
        libxslt
    brew install chromedriver --cask

else
    echo "Unsupported OS. Please install dependencies manually."
    exit 1
fi

echo "System dependencies installed successfully!"