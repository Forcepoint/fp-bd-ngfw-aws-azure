#!/bin/bash
shopt -s expand_aliases
alias python='python3'

apt install curl
apt install python3-venv
apt install python-ctypes

python3 Configure.py

python3 azure_agent_installer.py

# Install pip
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py

python3 -m pip install --user virtualenv

python3 -m venv venv

source venv/bin/activate

# Pip install requirements
python3 -m pip install -r requirements.txt

# Make Directory for NGFW integration
mkdir /opt/ngfw_2_cloud

# Move files to NGFW integration directory
cp -r ./* /opt/ngfw_2_cloud

# Copy service file to services directory
cp /opt/ngfw_2_cloud/SMC2CLOUD.service /lib/systemd/system/SMC2CLOUD.service

# Start service
systemctl daemon-reload
systemctl enable SMC2CLOUD
systemctl start SMC2CLOUD