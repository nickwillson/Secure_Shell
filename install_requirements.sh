#!/bin/bash

# List of dependencies
dependencies=("python3" "python3-pip" "python3-cryptography" "python3-openssl")

# Check if dependencies are installed
for dep in "${dependencies[@]}"; do
    if ! dpkg -s "$dep" >/dev/null 2>&1; then
        echo "Installing $dep"
        sudo apt-get install -y "$dep"
    else
        echo "$dep is already installed"
    fi
done
