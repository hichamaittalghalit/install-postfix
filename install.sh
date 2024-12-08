#!/usr/bin/env bash
set -euo pipefail

# Load environment variables from .env
if [ ! -f .env ]; then
    echo ".env file not found. Please create it before running this script."
    exit 1
fi

# shellcheck disable=SC1091
source .env

# Ensure required variables are set
: "${DOMAIN:?DOMAIN not set in .env}"
: "${IP:?IP not set in .env}"
: "${PORT:?PORT not set in .env}"
: "${MAIL_USERS:?MAIL_USERS not set in .env}"
: "${POSTFIX_CONF:?POSTFIX_CONF not set in .env}"
: "${VMAIL_DIR:?VMAIL_DIR not set in .env}"
: "${VMAIL_USER:?VMAIL_USER not set in .env}"
: "${VMAIL_UID:?VMAIL_UID not set in .env}"
: "${VMAIL_GID:?VMAIL_GID not set in .env}"

# Function to get password for a given user from environment variables
function get_password_for_user {
    local user_var_name
    # Convert username to uppercase and replace '.' with '_'
    user_var_name=$(echo "$1" | tr '[:lower:]' '[:upper:]' | tr '.' '_')
    user_var_name="${user_var_name}_PASSWORD"
    echo "${!user_var_name}"
}

############################################
# Reset environment (remove all services used)
############################################


# Uninstall apache if it's installed
if systemctl is-active --quiet apache2; then
    echo "Stopping and removing Apache..."
    sudo systemctl stop apache2
    sudo apt remove apache2 -y
    sudo apt purge apache2 -y
    sudo apt autoremove -y
fi

echo "Purging existing Postfix, Dovecot, OpenDKIM configurations..."

sudo systemctl stop postfix dovecot opendkim || true

sudo apt-get purge -y postfix dovecot-core dovecot-imapd dovecot-pop3d opendkim bind9
sudo apt-get autoremove -y
sudo rm -rf /etc/postfix /etc/dovecot /etc/opendkim /etc/bind
sudo deluser --remove-home vmail || true
sudo rm -rf "$VMAIL_DIR"

############################################
# Re-Install and Configure Everything
############################################

echo "Updating and installing required packages..."
sudo apt-get update -y

# Preseed Postfix debconf for non-interactive install
sudo debconf-set-selections <<< "postfix postfix/mailname string $DOMAIN"
sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

sudo apt-get install -y postfix dovecot-imapd dovecot-pop3d opendkim opendkim-tools openssl

# Create vmail user/group if not exists
if ! id "$VMAIL_USER" &>/dev/null; then
    sudo groupadd -g "$VMAIL_GID" "$VMAIL_USER"
    sudo useradd -g "$VMAIL_GID" -u "$VMAIL_UID" -d "$VMAIL_DIR" -m "$VMAIL_USER"
fi

sudo mkdir -p "$VMAIL_DIR"
sudo chown -R "$VMAIL_USER:$VMAIL_USER" "$VMAIL_DIR"
sudo chmod -R 770 "$VMAIL_DIR"

############################################
# Generate DKIM keys early so we can configure DNS
############################################

echo "Generating DKIM keys..."
sudo mkdir -p /etc/opendkim/keys
cd /etc/opendkim/keys
sudo opendkim-genkey -r -s default -d "$DOMAIN"
# default.txt contains the DKIM public key
sudo chown opendkim:opendkim default.private
sudo chmod go-rwx default.private

# Use grep directly on the file and include '--' to prevent interpretation of patterns as options
DKIM_RECORD=$(grep -v -- '-----' /etc/opendkim/keys/default.txt)

DKIM_VALUE=$(echo "$DKIM_RECORD" | sed -n 's/.*\(v=DKIM1[^"]*\).*/\1/p')

if [ -z "$DKIM_VALUE" ]; then
    echo "Error extracting DKIM record from default.txt"
    exit 1
fi

############################################
# Configure Postfix
############################################

echo "Configuring Postfix..."

sudo postconf -e "myhostname = mail.$DOMAIN"
sudo postconf -e "mydomain = $DOMAIN"
sudo postconf -e "myorigin = \$mydomain"
sudo postconf -e "inet_interfaces = all"
sudo postconf -e "inet_protocols = all"
sudo postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
sudo postconf -e "home_mailbox = Maildir/"
sudo postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"
sudo postconf -e "virtual_mailbox_domains = $DOMAIN"
sudo postconf -e "virtual_mailbox_base = $VMAIL_DIR"
sudo postconf -e "virtual_uid_maps = static:$VMAIL_UID"
sudo postconf -e "virtual_gid_maps = static:$VMAIL_GID"
sudo postconf -e "virtual_mailbox_maps = hash:/etc/postfix/vmailbox"
sudo postconf -e "smtpd_sasl_type = dovecot"
sudo postconf -e "smtpd_sasl_path = private/auth"
sudo postconf -e "smtpd_sasl_auth_enable = yes"
sudo postconf -e "smtpd_tls_security_level = may"
sudo postconf -e "smtp_tls_security_level = may"
sudo postconf -e "smtpd_tls_auth_only = yes"
sudo postconf -e "smtp_tls_note_starttls_offer = yes"
sudo postconf -e "smtpd_use_tls = yes"
sudo postconf -e "smtpd_tls_key_file = /etc/ssl/private/mail.key"
sudo postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/mail.crt"
sudo postconf -e "smtpd_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
sudo postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination"
sudo postconf -e "mynetworks = 127.0.0.0/8"
sudo postconf -e "mailbox_size_limit = 0"
sudo postconf -e "recipient_delimiter = +"
sudo postconf -e "inet_interfaces = all"
sudo postconf -e "inet_protocols = ipv4"
sudo postconf -e "smtpd_banner = \$myhostname ESMTP \$mail_name"

# Remove any existing submission block to avoid duplicates
sudo sed -i '/^submission /,/^$/d' /etc/postfix/master.cf

# Add the submission service configuration
{
    echo "submission     inet  n       -       y       -       -       smtpd"
    echo "  -o syslog_name=postfix"
    echo "  -o smtpd_tls_security_level=encrypt"
    echo "  -o smtpd_sasl_auth_enable=yes"
    echo "  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject"
    echo ""
} | sudo tee -a /etc/postfix/master.cf

# If using a different port than 587, add that port block as well
if [ "$PORT" != "587" ]; then
    sudo sed -i "/^$PORT /,/^$/d" /etc/postfix/master.cf
    {
        echo "$PORT     inet  n       -       y       -       -       smtpd"
        echo "  -o smtpd_tls_security_level=encrypt"
        echo "  -o smtpd_sasl_auth_enable=yes"
        echo "  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject"
        echo ""
    } | sudo tee -a /etc/postfix/master.cf
fi


############################################
# Set Up Virtual Mailboxes & Passwords
############################################

echo "Configuring virtual mailboxes..."
sudo touch /etc/postfix/vmailbox
sudo touch /etc/postfix/virtual
sudo postmap /etc/postfix/vmailbox
sudo postmap /etc/postfix/virtual

sudo mkdir -p /etc/dovecot
sudo touch /etc/dovecot/passwd
sudo chmod 600 /etc/dovecot/passwd

for USER in "${MAIL_USERS[@]}"; do
    MAILBOX="$USER@$DOMAIN"
    PASSWORD=$(get_password_for_user "$USER")
    MAILDIR="$VMAIL_DIR/$DOMAIN/$USER"
    sudo mkdir -p "$MAILDIR"
    sudo chown -R "$VMAIL_USER:$VMAIL_USER" "$VMAIL_DIR/$DOMAIN"
    sudo chmod -R 700 "$VMAIL_DIR/$DOMAIN"

    echo "$MAILBOX    $DOMAIN/$USER/" | sudo tee -a /etc/postfix/vmailbox

    HASHED_PASS=$(doveadm pw -s SHA512-CRYPT -p "$PASSWORD")
    echo "$MAILBOX:$HASHED_PASS:$VMAIL_UID:$VMAIL_GID::${VMAIL_DIR}/${DOMAIN}/${USER}::userdb_mail=maildir:${VMAIL_DIR}/${DOMAIN}/${USER}" | sudo tee -a /etc/dovecot/passwd
done

sudo postmap /etc/postfix/vmailbox

############################################
# Configure Dovecot
############################################

echo "Configuring Dovecot..."
sudo apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d

sudo tee /etc/dovecot/dovecot.conf > /dev/null <<EOF
disable_plaintext_auth = yes
listen = *
mail_privileged_group = mail
auth_mechanisms = plain login
!include_try /usr/share/dovecot/protocols.d/*.protocol
EOF

sudo tee /etc/dovecot/conf.d/10-mail.conf > /dev/null <<EOF
mail_location = maildir:${VMAIL_DIR}/%d/%n
namespace inbox {
  inbox = yes
}
mail_uid = ${VMAIL_UID}
mail_gid = ${VMAIL_GID}
EOF

sudo tee /etc/dovecot/conf.d/10-auth.conf > /dev/null <<EOF
disable_plaintext_auth = no
auth_mechanisms = plain login

passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/passwd
}

userdb {
  driver = static
  args = uid=${VMAIL_UID} gid=${VMAIL_GID} home=${VMAIL_DIR}/%d/%n
}
EOF

sudo tee /etc/dovecot/conf.d/10-ssl.conf > /dev/null <<EOF
ssl = yes
ssl_cert = </etc/ssl/certs/mail.crt
ssl_key = </etc/ssl/private/mail.key
EOF

sudo tee /etc/dovecot/conf.d/10-master.conf > /dev/null <<EOF
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF

############################################
# Generate Self-Signed TLS Certificates
############################################

echo "Generating self-signed TLS certificates..."
sudo mkdir -p /etc/ssl/private
sudo openssl req -new -x509 -days 365 -nodes -subj "/CN=mail.$DOMAIN" -out /etc/ssl/certs/mail.crt -keyout /etc/ssl/private/mail.key
sudo chmod 600 /etc/ssl/private/mail.key

############################################
# Configure OpenDKIM
############################################

echo "Configuring OpenDKIM..."

DKIM_KEY_DIR="/etc/opendkim/keys/$DOMAIN"
DKIM_SELECTOR="default"
DKIM_KEY_PUBLIC_FILE="$DKIM_KEY_DIR/$DKIM_SELECTOR.txt"
DKIM_KEY_PRIVATE_FILE="$DKIM_KEY_DIR/$DKIM_SELECTOR.private"

# Create the OpenDKIM user and group if they don't exist
if ! id "opendkim" &>/dev/null; then
    echo "Creating OpenDKIM user..."
    sudo adduser --system --group --no-create-home opendkim
fi

# Remove existing dkim folder if it exists
if [ -d "$DKIM_KEY_DIR" ]; then
    echo "Removing existing dkim folder: $DKIM_KEY_DIR"
    sudo rm -rf "$DKIM_KEY_DIR"
fi

sudo mkdir -p $DKIM_KEY_DIR
sudo opendkim-genkey -D "$DKIM_KEY_DIR/" -d "$DOMAIN" -s "$DKIM_SELECTOR" -b 1024
sudo chown -R opendkim:opendkim $DKIM_KEY_DIR
sudo chmod +r $DKIM_KEY_PUBLIC_FILE
sudo chmod go-w /etc/opendkim
sudo chmod 700 /etc/opendkim/keys

sudo tee /etc/opendkim.conf > /dev/null <<EOF
Syslog          Yes
UMask           002
# Use a local socket instead of inet
Socket          local:/run/opendkim/opendkim.sock
UserID          opendkim:opendkim
KeyTable        /etc/opendkim/KeyTable
SigningTable    /etc/opendkim/SigningTable
ExternalIgnoreList /etc/opendkim/TrustedHosts
InternalHosts   /etc/opendkim/TrustedHosts
Canonicalization relaxed/simple
Mode            sv
PidFile         /run/opendkim/opendkim.pid
EOF

echo "127.0.0.1" | sudo tee /etc/opendkim/TrustedHosts
echo "localhost" | sudo tee -a /etc/opendkim/TrustedHosts
echo "$DOMAIN" | sudo tee -a /etc/opendkim/TrustedHosts

sudo tee /etc/opendkim/KeyTable > /dev/null <<EOF
default._domainkey.$DOMAIN $DOMAIN:default:/etc/opendkim/keys/default.private
EOF

sudo tee /etc/opendkim/SigningTable > /dev/null <<EOF
*@$DOMAIN default._domainkey.$DOMAIN
EOF

# Ensure run directory for the socket and PID file is present
sudo mkdir -p /run/opendkim
sudo chown opendkim:opendkim /run/opendkim
sudo chmod 755 /run/opendkim

# Reload daemon to recognize any new unit configurations
sudo systemctl daemon-reload

# Enable and start OpenDKIM
sudo systemctl enable opendkim
sudo systemctl start opendkim

# Update Postfix to use the local socket milter
sudo postconf -e "milter_default_action = accept"
sudo postconf -e "milter_protocol = 2"
sudo postconf -e "smtpd_milters = local:/run/opendkim/opendkim.sock"
sudo postconf -e "non_smtpd_milters = local:/run/opendkim/opendkim.sock"

sudo systemctl restart postfix


############################################
# Setup Bind9 DNS Server
############################################


echo "Installing and configuring Bind9 for DNS..."
# Set up paths and variables
ZONE_DIR="/etc/bind/zones"
ZONE_FILE="$ZONE_DIR/db.$DOMAIN"

# Remove existing zone file if it exists
if [ -f "$ZONE_FILE" ]; then
    echo "Removing existing zone file: $ZONE_FILE"
    sudo rm "$ZONE_FILE"
fi

sudo apt-get install -y bind9 bind9utils

# Basic Bind9 configuration for authoritative DNS
sudo tee /etc/bind/named.conf.options > /dev/null <<EOF
options {
    directory "/var/cache/bind";
    recursion no;
    allow-transfer { none; };
    dnssec-validation no;
    listen-on { any; };
    listen-on-v6 { any; };
};
EOF

sudo tee /etc/bind/named.conf.local > /dev/null <<EOF
zone "$DOMAIN" {
    type master;
    file "/etc/bind/db.$DOMAIN";
};
EOF

# Generate the date-based serial in YYYYMMDD01 format
SERIAL=$(date +"%Y%m%d01")

DKIM_VALUE=$(cat "$DKIM_KEY_PUBLIC_FILE" | tr -d '\t' | tr -d '\n' | grep -oP '\(\s*\K[^)]*' | tr -d ' "' | sed 's/;/; /g')

# Write the zone file with correct formatting
sudo tee "$ZONE_FILE" > /dev/null <<EOF
\$TTL 300
@   IN  SOA ns1.$DOMAIN. admin.$DOMAIN. (
        $SERIAL     ; Serial (YYYYMMDD01 format)
        3600        ; Refresh - 1 hour
        1800        ; Retry - 30 minutes
        1209600     ; Expire - 2 weeks
        300 )       ; Minimum TTL - 5 minutes

; Name Servers
@   IN  NS  ns1.$DOMAIN.
@   IN  NS  ns2.$DOMAIN.

; A Records
@       IN  A   $IP
ns1     IN  A   $IP
ns2     IN  A   $IP
mail    IN  A   $IP
www     IN  A   $IP

; MX Record
@   IN  MX  10 mail.$DOMAIN.

; SPF Record
@   IN  TXT "v=spf1 ip4:$IP ~all"

; DKIM TXT Record
$DKIM_SELECTOR._domainkey IN TXT "$DKIM_VALUE"

; DMARC Record
_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:$SUPPORT_EMAIL; ruf=mailto:$SUPPORT_EMAIL; pct=100; aspf=s;"
EOF

# Setup BIND configuration
echo "Setting up BIND for $DOMAIN..."
if ! grep -q "zone \"$DOMAIN\"" /etc/bind/named.conf.local; then
    echo "zone \"$DOMAIN\" {
    type master;
    file \"$ZONE_FILE\";
};" | sudo tee -a /etc/bind/named.conf.local
fi

# Check and reload BIND configuration
echo "Checking BIND configuration..."
sudo named-checkconf
sudo named-checkzone "$DOMAIN" "$ZONE_FILE"

sudo systemctl restart bind9

###########################################
# NGINX HTTPS 
###########################################
# Define the NGINX configuration paths
NGINX_CONF_PATH="/etc/nginx/sites-available/$DOMAIN"
NGINX_ENABLED_LINK="/etc/nginx/sites-enabled/$DOMAIN"
DEFAULT_CONF_PATH="/etc/nginx/sites-available/default"
DEFAULT_ENABLED_LINK="/etc/nginx/sites-enabled/default"

# Step 1: Remove old NGINX configuration if it exists
if [ -e "$NGINX_CONF_PATH" ]; then
    echo "Deleting old NGINX configuration in $NGINX_CONF_PATH ..."
    sudo rm -rf "$NGINX_CONF_PATH"
fi

# Step 2: Remove the symlink if it exists
if [ -L "$NGINX_ENABLED_LINK" ]; then
    echo "Removing existing symbolic link for $DOMAIN ..."
    sudo rm "$NGINX_ENABLED_LINK"
elif [ -e "$NGINX_ENABLED_LINK" ]; then
    echo "Removing existing file for $DOMAIN ..."
    sudo rm -f "$NGINX_ENABLED_LINK"
fi

# Step 3: Create the NGINX configuration directory
sudo mkdir -p "$NGINX_CONF_PATH"

# Step 4: Create the initial NGINX configuration for the domain (HTTP only)
NGINX_CONF="$NGINX_CONF_PATH/nginx.conf"
echo "Creating NGINX configuration for $DOMAIN ..."
sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME *.${DOMAIN_NAME};

    # Redirect all HTTP requests to HTTPS
    return 301 https://\$host\$request_uri;
}
EOF

# Step 5: Create the web root directory
sudo mkdir -p "/var/www/$DOMAIN"
echo "<h1>Welcome to $DOMAIN</h1>" | sudo tee "/var/www/$DOMAIN/index.html" > /dev/null

# Step 6: Create a symbolic link in sites-enabled
echo "Creating symlink to NGINX configuration in sites-enabled ..."
sudo ln -s "$NGINX_CONF" "$NGINX_ENABLED_LINK"

# Step 7: Obtain the certificate for the main domain and wildcard subdomain
echo "Obtaining TLS certificate for $DOMAIN..."

if ! sudo certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos --email "$SUPPORT_EMAIL"; then
    echo "Failed to obtain SSL certificate. Please check the errors above."
    exit 1
fi

# Step 8: Append the SSL configuration to the NGINX configuration
echo "Adding SSL configuration to NGINX configuration for $DOMAIN ..."
# Create or overwrite the NGINX configuration
sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME *.$DOMAIN_NAME;

    # Redirect all HTTP requests to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $DOMAIN *.$DOMAIN;

    # SSL certificate paths
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;  # Change this path if necessary
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;  # Change this path if necessary

    # Root directory and index file
    root /var/www/$DOMAIN;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;  # Serve files or return 404
    }
}
EOF

# Step 9: Test the NGINX configuration
echo "Testing the NGINX configuration..."
if sudo nginx -t; then
    echo "NGINX configuration is valid. Reloading NGINX..."
    sudo systemctl reload nginx
else
    echo "NGINX configuration test failed. Please check the configuration file for errors."
    exit 1  # Exit with an error status
fi

# Step 10: Set up automatic renewal with a cron job
if ! crontab -l | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/certbot renew --quiet") | crontab -
fi

echo "TLS certificate installed for $DOMAIN with auto-renewal configured."

# Optional: Self-Signed Certificate Setup (if needed)
DAYS_VALID=365
SELF_SIGNED_CERT_DIR="/etc/ssl/selfsigned"
SELF_SIGNED_CERT_KEY="${SELF_SIGNED_CERT_DIR}/selfsigned.key"
SELF_SIGNED_CERT_CRT="${SELF_SIGNED_CERT_DIR}/selfsigned.crt"

# Create directory for self-signed certs
sudo mkdir -p "${SELF_SIGNED_CERT_DIR}"

# Generate a self-signed certificate for the IP address
sudo openssl req -x509 -nodes -days "${DAYS_VALID}" -newkey rsa:2048 \
    -keyout "${SELF_SIGNED_CERT_KEY}" -out "${SELF_SIGNED_CERT_CRT}" \
    -subj "/CN=${ADDRESS_IP}"

echo "Self-signed certificate created:"
echo "Key: ${SELF_SIGNED_CERT_KEY}"
echo "Certificate: ${SELF_SIGNED_CERT_CRT}"

############################################
# Restart Services
############################################

sudo systemctl enable opendkim
sudo systemctl restart opendkim
sudo systemctl restart postfix
sudo systemctl restart dovecot
sudo systemctl restart bind9
sudo systemctl restart nginx

echo "Postfix, Dovecot, OpenDKIM, and DNS configuration completed without printing DNS instructions."
echo "Ensure your domain's nameservers point to this server to use the configured DNS records."
