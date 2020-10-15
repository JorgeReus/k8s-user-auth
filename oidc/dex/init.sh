#!/bin/bash

# Dependecies
export GOPATH=/home/ubuntu/go
sudo apt update
sudo apt update
sudo apt install -y golang make
go get github.com/dexidp/dex
cd $GOPATH/src/github.com/dexidp/dex
make
mv web /home/ubuntu/dex/
sudo mv bin/dex /usr/bin/

# Systemd Service
sudo tee /etc/systemd/system/dex.service > /dev/null <<'EOF'
[Unit]
Description=Dex service k8s OICD authentication

[Service]
ExecStart=/usr/bin/dex serve /home/ubuntu/dex/server-config.yaml

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl start dex
