#!/bin/bash

# Check if python3 is installed
if ! command -v python3 &>/dev/null; then
    sudo apt-get update
    sudo apt-get install -y python3
fi

# Check if pip3 is installed
if ! command -v pip3 &>/dev/null; then
    sudo apt-get install -y python3-pip
fi

# Install required Python packages
sudo pip3 install -r requirements.txt
