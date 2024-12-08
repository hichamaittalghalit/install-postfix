#!/bin/bash

# Charger les variables depuis le fichier .env dans le répertoire courant
ENV_FILE="$(pwd)/.env"

if [ -f "$ENV_FILE" ]; then
  echo "Chargement des variables depuis $ENV_FILE..."
  source "$ENV_FILE"
else
  echo "Erreur : le fichier .env n'existe pas dans $(pwd). Veuillez le créer avec vos valeurs."
  exit 1
fi

# Vérification des variables essentielles
if [ -z "$DOMAIN" ] || [ -z "$IP" ] || [ -z "$PORT" ] || [ -z "${MAIL_USERS[*]}" ]; then
  echo "Erreur : certaines variables essentielles sont manquantes dans $ENV_FILE."
  exit 1
fi

POSTFIX_CONF="$POSTFIX_CONF"
PASSWORD_FILE="/etc/postfix/virtual_mailbox_passwords"

# Configuration de debconf pour Postfix (mode non-interactif)
echo "Configuration de debconf pour une installation silencieuse de Postfix..."
export DEBIAN_FRONTEND=noninteractive
echo "postfix postfix/main_mailer_type string Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string $DOMAIN" | debconf-set-selections

# Mise à jour et installation des dépendances
echo "Mise à jour et installation des paquets nécessaires..."
apt update && apt upgrade -y
apt install -y postfix dovecot-core dovecot-imapd dovecot-pop3d mailutils bind9 certbot opendkim opendkim-tools

# Configuration des groupes et des utilisateurs virtuels
echo "Configuration des utilisateurs virtuels..."
groupadd -g $VMAIL_GID $VMAIL_USER || true
useradd -m -d $VMAIL_DIR -u $VMAIL_UID -g $VMAIL_GID -s /usr/sbin/nologin $VMAIL_USER || true
mkdir -p $VMAIL_DIR
chown -R $VMAIL_USER:$VMAIL_USER $VMAIL_DIR

# Configuration principale de Postfix
echo "Configuration de Postfix..."
cat <<EOF > $POSTFIX_CONF
# Configuration principale de Postfix
myhostname = mail.$DOMAIN
mydomain = $DOMAIN
myorigin = /etc/mailname
inet_interfaces = all
inet_protocols = ipv4
mydestination = \$myhostname, localhost.\$mydomain, localhost
virtual_mailbox_domains = $DOMAIN
virtual_mailbox_base = $VMAIL_DIR
virtual_mailbox_maps = hash:$PASSWORD_FILE
virtual_alias_maps = hash:$PASSWORD_FILE
virtual_uid_maps = static:$VMAIL_UID
virtual_gid_maps = static:$VMAIL_GID
smtpd_tls_cert_file=/etc/ssl/certs/mail.$DOMAIN.pem
smtpd_tls_key_file=/etc/ssl/private/mail.$DOMAIN.key
smtpd_use_tls=yes
smtpd_sasl_auth_enable = yes
broken_sasl_auth_clients = yes
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
EOF

# Configuration DKIM avec OpenDKIM
echo "Configuration DKIM..."
cat <<EOF > /etc/opendkim.conf
Syslog                  yes
UMask                   002
Domain                  $DOMAIN
KeyFile                 /etc/opendkim/keys/$DOMAIN/mail.private
Selector                mail
Socket                  inet:12301@localhost
EOF

mkdir -p /etc/opendkim/keys/$DOMAIN
opendkim-genkey -s mail -d $DOMAIN
chown -R opendkim:opendkim /etc/opendkim/keys

# Configuration Bind9 pour SPF, DKIM et DMARC
echo "Configuration Bind9 pour SPF, DKIM et DMARC..."
cat <<EOF > /etc/bind/db.$DOMAIN
\$TTL 604800
@   IN  SOA ns1.$DOMAIN. admin.$DOMAIN. (
             2         ; Serial
        604800         ; Refresh
         86400         ; Retry
       2419200         ; Expire
        604800 )       ; Negative Cache TTL

; Serveurs DNS
@       IN  NS      ns1.$DOMAIN.
@       IN  NS      ns2.$DOMAIN.

; A Records
@       IN  A       $IP
ns1     IN  A       $IP
ns2     IN  A       $IP
mail    IN  A       $IP

; MX Records
@       IN  MX 10   mail.$DOMAIN.

; TXT Records
@       IN  TXT     "v=spf1 mx a ~all"
mail    IN  TXT     "v=DKIM1; k=rsa; p=$(awk 'NR>2' /etc/opendkim/keys/$DOMAIN/mail.txt | tr -d '\n')"
_dmarc  IN  TXT     "v=DMARC1; p=none; rua=mailto:dmarc@$DOMAIN"
EOF

# Création des mots de passe pour les utilisateurs virtuels
echo "Création des mots de passe pour les utilisateurs virtuels..."
touch $PASSWORD_FILE
chmod 600 $PASSWORD_FILE
for user in "${MAIL_USERS[@]}"; do
    VAR_NAME="${user^^}_PASSWORD"
    PASSWORD=${!VAR_NAME}

    if [ -z "$PASSWORD" ]; then
        echo "Erreur : le mot de passe pour $user est manquant dans $ENV_FILE."
        exit 1
    fi

    echo "$user@$DOMAIN $VMAIL_DIR/$DOMAIN/$user/" >> /etc/postfix/virtual_mailbox_maps
    echo "$user@$DOMAIN:$PASSWORD" >> $PASSWORD_FILE
done

postmap /etc/postfix/virtual_mailbox_maps

# Redémarrage des services
echo "Redémarrage des services nécessaires..."
systemctl restart postfix
systemctl restart dovecot
systemctl restart bind9
systemctl restart opendkim

echo "Configuration terminée avec succès."
echo "Les mots de passe ont été utilisés à partir de $ENV_FILE."
