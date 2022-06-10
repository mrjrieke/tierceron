#!/bin/bash -e

# Install packages
sudo apt-get update -y
sudo apt-get install -y curl unzip

# Download Vault into some temporary directory
curl -L "https://releases.hashicorp.com/vault/0.10.1/vault_0.10.1_linux_amd64.zip" > /tmp/vault.zip

cd /tmp
sudo -- sh -c "echo '127.0.0.1 $(hostname)' >> /etc/hosts"
sudo unzip vault.zip
sudo mkdir -p /usr/src/app
sudo mv vault /usr/src/app/vault
sudo chmod 0755 /usr/src/app/vault
sudo chown root:root /usr/src/app/vault
sudo mkdir -p /etc/opt/vault/data/
#make directory etc/opt/vault
sudo mkdir -p /etc/opt/vault/certs/
#copy everything from /tmp
sudo mv /tmp/serv_*.pem /etc/opt/vault/certs/
sudo mv /tmp/Digi*.crt.pem /etc/opt/vault/certs/
privateip=$(hostname -I | cut -d' ' -f1); sed -i "s/127.0.0.1/$privateip/g" /tmp/vault_properties.hcl
#get pem files locally 
sudo mv /tmp/vault_properties.hcl /etc/opt/vault/vault_properties.hcl
sudo chown root:root /etc/opt/vault/vault_properties.hcl


# Setup the init script

# Using heredoc '<<'' in terraform doesn't
# allow for terraform variable substitution.
# it's neccessary to insert '<<' as a variable
# to add the host and host port to the script.
# ${write_service} serves this purpose.
cat ${write_service} EOF >/tmp/upstart
[Unit]
Description=Vault Service
After=systemd-user-sessions.service
[Service]

Type=simple
Environment="VAULT_API_ADDR=https://${HOST}:${HOSTPORT}"
Environment="GOMAXPROCS=$(nproc)"
ExecStart=/usr/src/app/vault server -config /etc/opt/vault/vault_properties.hcl
LimitMEMLOCK=infinity

#end script
EOF
sudo mv /tmp/upstart /lib/systemd/system/vault.service

# Start Vault
sudo service vault start