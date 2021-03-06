#!/bin/sh

#
# This script provides a basic way of configuring a single Ubuntu machine in accordance
# with the attached End User Device guidance. This script contains sugegstions only and
# should be customised for individual user needs. In particular it will likely not scale
# to large deployments; in those scenarios a purpose-built tool should handle the roll-
# out and deployment of these devices. SCM tools, preseed scripts and automated technology
# such as PXE boot scripts should be used instead.
# From:
# https://www.gov.uk/government/uploads/system/uploads/attachment_data/file/413162/install.sh.txt

if ! [ $(id -u) = 0 ]; then
   echo "This script needs to be run as root (with sudo)."
   exit 1
   else
   echo "\n... Running as root.\n"
fi

# Prompt for whether an SCM will be used or not
echo "\nYou can have this script perform configuration now.\n"
while [ "$DOCONFIG" != "y" -a "$DOCONFIG" != "n" ]; do read -p "Should the script perform configuration? [y/n]: " DOCONFIG; done

# Some variables needed later.
GS="/usr/bin/gsettings"
CCUL="com.canonical.Unity.lenses"

if [ "$DOCONFIG" = "y" ]; then
  echo "\n\n... Applying recommended system settings...\n"
  
# Enable automatic updates
echo "\n... Enable automatic updates"
  echo "APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";
" >> /etc/apt/apt.conf.d/20auto-upgrades
  chmod 644 /etc/apt/apt.conf.d/20auto-upgrades

# Disable guest login
echo "\n... Disable guest login"
  mkdir /etc/lightdm/lightdm.conf.d
  echo "[SeatDefaults]
allow-guest=false
" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf

# A hook to disable online scopes in dash on login
echo "\n... A hook to disable online scopes in dash on login"
  echo '#!/bin/bash' > /usr/local/bin/unity-privacy-hook.sh
  echo "gsettings set com.canonical.Unity.Lenses remote-content-search 'none'
gsettings set com.canonical.Unity.Lenses disabled-scopes \"['more_suggestions-amazon.scope', 'more_suggestions-u1ms.scope', 'more_suggestions-populartracks.scope', 'music-musicstore.scope', 'more_suggestions-ebay.scope', 'more_suggestions-ubuntushop.scope', 'more_suggestions-skimlinks.scope']\"
for USER in \`ls -1 /home\`; do
  chown \"\$USER\":\"\$USER\" /home/\"\$USER\"/.*
done
exit 0
" >> /usr/local/bin/unity-privacy-hook.sh
  chmod 755 /usr/local/bin/unity-privacy-hook.sh
  echo "[SeatDefaults]
session-setup-script=/usr/local/bin/unity-privacy-hook.sh" > /etc/lightdm/lightdm.conf.d/20privacy-hook.conf

fi

# Refresh the package list
echo "\n...Refresh the package list"
#apt-get update

# Install extra packages
echo "\n... Install extra packages"
apt-get install -y vim iotop dstat vlc openssh-server apparmor-profiles apparmor-utils

# Set some AppArmor profiles to enforce mode
echo "\n... Set some AppArmor profiles to enforce mode"
aa-enforce /etc/apparmor.d/usr.bin.firefox
aa-enforce /etc/apparmor.d/usr.sbin.avahi-daemon
aa-enforce /etc/apparmor.d/usr.sbin.dnsmasq
aa-enforce /etc/apparmor.d/bin.ping
aa-enforce /etc/apparmor.d/usr.sbin.rsyslogd


# Turn off privacy-leaking aspects of Unity
echo "\n... Turn off privacy-leaking aspects of Unity"
$GS set "$CCUL" remote-content-search none
$GS set "$CCUL" disabled-scopes \
    "['more_suggestions-amazon.scope', 'more_suggestions-u1ms.scope',
    'more_suggestions-populartracks.scope', 'music-musicstore.scope',
    'more_suggestions-ebay.scope', 'more_suggestions-ubuntushop.scope',
    'more_suggestions-skimlinks.scope']"
echo "user-db:user" > /etc/dconf/profile/user
echo "system-db:local" >> /etc/dconf/profile/user
mkdir -p /etc/dconf/db/local.d
echo "[com/canonical/unity/lenses]" > /etc/dconf/db/local.d/unity
echo "remote-content-search=false" >> /etc/dconf/db/local.d/unity
mkdir -p /etc/dconf/db/local.d/locks
echo "/com/canonical/unity/lenses/remote-content-search" > /etc/dconf/db/local.d/locks/unity
dconf update

# Improve SSH security
echo "\n... Improving SSH security, this will take a while."
echo "... This is the last step before running a dist-upgrade."
echo "... dist-upgrade is the last step.\n"

# Try to find config files {{{
SSH_CONFIG_DIR="/etc/ssh"
SSHD_CONFIG="/etc/ssh/sshd_config";
SSH_CONFIG="/etc/ssh/ssh_config";

# Fix sshd config
        echo "\n... Fix sshd config"
        lines_inserted=0;

        # Fix key exchange algorithm settings if needed
        grep '^\s*KexAlgorithms\s\+' "$SSHD_CONFIG" &>/dev/null;
                echo "\n... Fix key exchange algorithm settings if needed"
                sed -i 's/^\(\s*\)KexAlgorithms\s\+.*$/\1KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256/' "$SSHD_CONFIG";
            sleep 1

        # If the moduli file exists, get rid of any primes less than 2000 bits
	rm "$SSH_CONFIG_DIR/moduli";
    
        # If there's nothing left in the moduli file (or it didn't exist at all), we should populate it
        if [ "$(stat --printf=%s "$MODULI")" -lt 10 ]; then
                echo "\n... If there's nothing left in the moduli file (or it didn't exist at all), we should populate it"
                rm "$MODULI";
                ssh-keygen -q -G "$SSHD_CONFIG_DIR"/moduli.tmp -b 4096
                ssh-keygen -T "$MODULI" -f "$SSHD_CONFIG_DIR/moduli.tmp"
                rm -f "$SSHD_CONFIG_DIR/moduli.tmp"
                sleep 1
        fi;

        # Force v2 protocol
        grep '^\s*Protocol\s\+' "$SSHD_CONFIG" &>/dev/null;
                echo "\n... Force v2 protocol"
                sed -i 's/^\(\s*\)Protocol\s\+.*$/\1Protocol 2/' "$SSHD_CONFIG";
                sleep 1

        # Get rid of DSA and ECDSA keys; create RSA and Ed25519 if they don't exist
        echo "\n... Get rid of DSA and ECDSA keys; create RSA and Ed25519 if they don't exist"
        sed -i '/^\s*HostKey/d' "$SSHD_CONFIG";
        sleep 1
        lines_inserted=$((${lines_inserted} + 1));
        sed -i "${lines_inserted}iHostKey ${SSHD_CONFIG}/ssh_host_ed25519_key" "$SSHD_CONFIG";
        sleep 1
        lines_inserted=$((${lines_inserted} + 1));
        sed -i "${lines_inserted}iHostKey ${SSHD_CONFIG}/ssh_host_rsa_key" "$SSHD_CONFIG";
        sleep 1
        rm -f "${SSHD_CONFIG}/ssh_host_key{,.pub}";
        sleep 1
        rm -f "${SSHD_CONFIG}/ssh_host_dsa_key{,.pub}";
        sleep 1
        rm -f "${SSHD_CONFIG}/ssh_host_ecdsa_key{,.pub}";
        sleep 1
        rm -f "${SSHD_CONFIG}/ssh_host_rsa_key{,.pub}";
        sleep 1
        if [ ! -f "${SSHD_CONFIG}/ssh_host_ed25519_key" ] || [ ! -f "${SSHD_CONFIG}/ssh_host_ed25519_key.pub" ]; then
                ssh-keygen -t ed25519 -f "${SSHD_CONFIG}/ssh_host_ed25519_key" < /dev/null;
                sleep 1
        fi;
        if [ ! -f "${SSHD_CONFIG}/ssh_host_rsa_key" ] || [ ! -f "${SSHD_CONFIG}/ssh_host_rsa_key.pub" ]; then
                ssh-keygen -t rsa -b 4096 -f "${SSHD_CONFIG}/ssh_host_rsa_key" < /dev/null;
                sleep 1
        fi;

        # Limit symmetric ciphers to good modern ones
        grep '^\s*Ciphers\s\+' "$SSHD_CONFIG" &>/dev/null;
                echo "\n... Limit symmetric ciphers to good modern ones"
                sed -i 's/^\(\s*\)Ciphers\s\+.*$/\1Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr/' "$SSHD_CONFIG";
                sleep 1

        # Limit MAC algos to good modern ones with long keys, ETM only
        grep '^\s*MACs\s\+' "$SSHD_CONFIG" &>/dev/null;
                echo "\n... Limit MAC algos to good modern ones with long keys, ETM only"
                sed -i 's/^\(\s*\)MACs\s\+.*$/\1MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com/' "$SSHD_CONFIG";
                sleep 1

# Some settings
echo "\n... Disable logout, restart and shutdown prompts."
$GS set com.canonical.indicator.session suppress-logout-restart-shutdown true

# Create dist-upgrade script in home dir.
echo "\n... Create dist-upgrade script in home dir."
echo "echo ... Update [Start]" > ~/dist-upgrade
echo "sudo apt-get update" >> ~/dist-upgrade
echo "echo ... Update [Done]" >> ~/dist-upgrade
echo "" >> ~/dist-upgrade
echo "echo ... Clean [Start]" >> ~/dist-upgrade
echo "sudo apt-get clean" >> ~/dist-upgrade
echo "echo ... Clean [Done]" >> ~/dist-upgrade
echo "" >> ~/dist-upgrade
echo "echo ... Autoclean [Start]" >> ~/dist-upgrade
echo "sudo apt-get autoclean" >> ~/dist-upgrade
echo "echo ... Autoclean [Done]" >> ~/dist-upgrade
echo "" >> ~/dist-upgrade
echo "echo ... Dist-upgrade [Start]" >> ~/dist-upgrade
echo "sudo apt-get dist-upgrade" >> ~/dist-upgrade
echo "echo ... Dist-upgrade [Done]" >> ~/dist-upgrade
chmod +x ~/dist-upgrade

# Upgrade the system
echo "\n... Upgrade the system"
apt-get dist-upgrade -y

echo -e "\nPOST INSTALLATION COMPLETE\n"
