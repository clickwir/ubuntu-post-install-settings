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
   echo "\nRunning as root.\n"
fi

# Prompt for whether an SCM will be used or not
echo -e "\nYou can have this script perform configuration now.\n"
while [ "$DOCONFIG" != "y" -a "$DOCONFIG" != "n" ]; do read -p "Should the script perform configuration? [y/n]: " DOCONFIG; done

# Some variables needed later.
GS="/usr/bin/gsettings"
CCUL="com.canonical.Unity.lenses"

if [ "$DOCONFIG" = "y" ]; then
  echo -e "\n\nApplying recommended system settings...\n"

  while [ -z "$ADMINUSER" ]; do read -p "Enter the name of the user you created in the GUI: " ADMINUSER; done

  # Enable automatic updates
  echo "APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";
" >> /mnt/etc/apt/apt.conf.d/20auto-upgrades
  chmod 644 /mnt/etc/apt/apt.conf.d/20auto-upgrades

  # Disable guest login
  mkdir /mnt/etc/lightdm/lightdm.conf.d
  echo "[SeatDefaults]
allow-guest=false
" > /mnt/etc/lightdm/lightdm.conf.d/50-no-guest.conf

  # A hook to disable online scopes in dash on login
  echo '#!/bin/bash' > /mnt/usr/local/bin/unity-privacy-hook.sh
  echo "gsettings set com.canonical.Unity.Lenses remote-content-search 'none'
gsettings set com.canonical.Unity.Lenses disabled-scopes \"['more_suggestions-amazon.scope', 'more_suggestions-u1ms.scope', 'more_suggestions-populartracks.scope', 'music-musicstore.scope', 'more_suggestions-ebay.scope', 'more_suggestions-ubuntushop.scope', 'more_suggestions-skimlinks.scope']\"
for USER in \`ls -1 /home\`; do
  chown \"\$USER\":\"\$USER\" /home/\"\$USER\"/.*
done
exit 0
" >> /mnt/usr/local/bin/unity-privacy-hook.sh
  chmod 755 /mnt/usr/local/bin/unity-privacy-hook.sh
  echo "[SeatDefaults]
session-setup-script=/usr/local/bin/unity-privacy-hook.sh" > /mnt/etc/lightdm/lightdm.conf.d/20privacy-hook.conf

fi

echo -e "\nINSTALLATION COMPLETE\n"
if [ "$DOCONFIG" = "y" ]; then
  echo "Remember to run the post installation script after rebooting to finalise configuration."
fi

# Refresh the package list
apt-get update

# Install extra packages
apt-get install -y vim iotop dstat vlc openssh-server apparmor-profiles apparmor-utils

# Set some AppArmor profiles to enforce mode
aa-enforce /etc/apparmor.d/usr.bin.firefox
aa-enforce /etc/apparmor.d/usr.sbin.avahi-daemon
aa-enforce /etc/apparmor.d/usr.sbin.dnsmasq
aa-enforce /etc/apparmor.d/bin.ping
aa-enforce /etc/apparmor.d/usr.sbin.rsyslogd


# Turn off privacy-leaking aspects of Unity
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
# Usage and argument parsing {{{
#usage() {
#        echo "usage: $0 [options]";
#        echo;
#        echo "OPTIONS";
#        echo "  -h      Show this help message";
#        echo "  -d      Dry run - echo what we want to do, but don't do it";
#        echo;
#}

echo "Improving SSH security, this will take a while."
echo "This is the last step before running a dist-upgrade."
echo "dist-upgrade is the last step."

DRY_RUN=0;
while getopts 'hd' option; do
        case "$option" in
                'h')
                        usage;
                        exit 1;
                        ;;
                'd')
                        DRY_RUN=1;
                        ;;
                ?)
                        usage;
                        exit 1;
                        ;;
        esac;
done;
# }}}

runcmd() { # {{{
        echo "+++ $@";
        if [ "$DRY_RUN" -eq 0 ]; then
                cmd="$1";
                shift;
                $cmd "$@";
        fi;
} # }}}

# Try to find config files {{{
SSHD_CONFIG_POSSIBILITIES=(
        '/etc/ssh/sshd_config'
        '/etc/sshd_config'
);
SSH_CONFIG_POSSIBILITIES=(
        '/etc/ssh/ssh_config'
        '/etc/ssh_config'
);

SSHD_CONFIG='';
SSH_CONFIG='';

for file in ${SSHD_CONFIG_POSSIBILITIES[*]}; do
        if [ -f "$file" ]; then
                echo "--- Found SSHD_CONFIG at ${file}";
                SSHD_CONFIG="${file}";
                break;
        fi;
done

for file in ${SSH_CONFIG_POSSIBILITIES[*]}; do
        if [ -f "$file" ]; then
                echo "--- Found SSH_CONFIG at ${file}";
                SSH_CONFIG="${file}";
                break;
        fi;
done;
# }}}

# Fix sshd config if we found it {{{
if [ "$SSHD_CONFIG" != '' ]; then
        SSHD_CONFIG_DIR="$(dirname "$SSHD_CONFIG")";
        lines_inserted=0;

        # Fix key exchange algorithm settings if needed
        grep '^\s*KexAlgorithms\s\+' "$SSHD_CONFIG" &>/dev/null;
        if [ "$?" -eq 0 ]; then
                runcmd sed -i 's/^\(\s*\)KexAlgorithms\s\+.*$/\1KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256/' "$SSHD_CONFIG";
                sleep 1
        else
                lines_inserted=$((${lines_inserted} + 1));
                runcmd sed -i "${lines_inserted}i\\KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" "$SSHD_CONFIG";
                sleep 1
        fi;

        # If the moduli file exists, get rid of any primes less than 2000 bits
        MODULI="${SSHD_CONFIG_DIR}/moduli";
        if [ -f "$MODULI" ]; then
                # Ugly hack for portable in-place awk
                runcmd awk '$5 > 2000' "$MODULI" > >(cat <(sleep 1) - > "$MODULI");
                sleep 1
        else
                runcmd touch "$MODULI";
                sleep 1
        fi;

        # If there's nothing left in the moduli file (or it didn't exist at all), we should populate it
        if [ "$(stat --printf=%s "$MODULI")" -lt 10 ]; then
                runcmd rm "$MODULI";
                runcmd ssh-keygen -q -G "$SSHD_CONFIG_DIR"/moduli.tmp -b 4096
                runcmd ssh-keygen -T "$MODULI" -f "$SSHD_CONFIG_DIR/moduli.tmp"
                runcmd rm -f "$SSHD_CONFIG_DIR/moduli.tmp"
                sleep 1
        fi;

        # Force v2 protocol
        grep '^\s*Protocol\s\+' "$SSHD_CONFIG" &>/dev/null;
        if [ "$?" -eq 0 ]; then
                runcmd sed -i 's/^\(\s*\)Protocol\s\+.*$/\1Protocol 2/' "$SSHD_CONFIG";
                sleep 1
        else
                lines_inserted=$((${lines_inserted} + 1));
                runcmd sed -i "${lines_inserted}iProtocol 2" "$SSHD_CONFIG";
                sleep 1
        fi;

        # Get rid of DSA and ECDSA keys; create RSA and Ed25519 if they don't exist
        runcmd sed -i '/^\s*HostKey/d' "$SSHD_CONFIG";
        sleep 1
        lines_inserted=$((${lines_inserted} + 1));
        runcmd sed -i "${lines_inserted}iHostKey ${SSHD_CONFIG_DIR}/ssh_host_ed25519_key" "$SSHD_CONFIG";
        sleep 1
        lines_inserted=$((${lines_inserted} + 1));
        runcmd sed -i "${lines_inserted}iHostKey ${SSHD_CONFIG_DIR}/ssh_host_rsa_key" "$SSHD_CONFIG";
        sleep 1
        runcmd rm -f "${SSHD_CONFIG_DIR}/ssh_host_key{,.pub}";
        sleep 1
        runcmd rm -f "${SSHD_CONFIG_DIR}/ssh_host_dsa_key{,.pub}";
        sleep 1
        runcmd rm -f "${SSHD_CONFIG_DIR}/ssh_host_ecdsa_key{,.pub}";
        sleep 1
        runcmd rm -f "${SSHD_CONFIG_DIR}/ssh_host_rsa_key{,.pub}";
        sleep 1
        if [ ! -f "${SSHD_CONFIG_DIR}/ssh_host_ed25519_key" ] || [ ! -f "${SSHD_CONFIG_DIR}/ssh_host_ed25519_key.pub" ]; then
                runcmd ssh-keygen -t ed25519 -f "${SSHD_CONFIG_DIR}/ssh_host_ed25519_key" < /dev/null;
                sleep 1
        fi;
        if [ ! -f "${SSHD_CONFIG_DIR}/ssh_host_rsa_key" ] || [ ! -f "${SSHD_CONFIG_DIR}/ssh_host_rsa_key.pub" ]; then
                runcmd ssh-keygen -t rsa -b 4096 -f "${SSHD_CONFIG_DIR}/ssh_host_rsa_key" < /dev/null;
                sleep 1
        fi;

        # Limit symmetric ciphers to good modern ones
        grep '^\s*Ciphers\s\+' "$SSHD_CONFIG" &>/dev/null;
        if [ "$?" -eq 0 ]; then
                runcmd sed -i 's/^\(\s*\)Ciphers\s\+.*$/\1Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr/' "$SSHD_CONFIG";
                sleep 1
        else
                lines_inserted=$((${lines_inserted} + 1));
                runcmd sed -i "${lines_inserted}iCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "$SSHD_CONFIG";
                sleep 1
        fi;

        # Limit MAC algos to good modern ones with long keys, ETM only
        grep '^\s*MACs\s\+' "$SSHD_CONFIG" &>/dev/null;
        if [ "$?" -eq 0 ]; then
                runcmd sed -i 's/^\(\s*\)MACs\s\+.*$/\1MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com/' "$SSHD_CONFIG";
                sleep 1
        else
                lines_inserted=$((${lines_inserted} + 1));
                runcmd sed -i "${lines_inserted}iMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com" "$SSHD_CONFIG";
                sleep 1
        fi;
fi;
# }}}

# Some settings
$GS set com.canonical.indicator.session suppress-logout-restart-shutdown true

# Create dist-upgrade script in home dir.
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
apt-get dist-upgrade -y

echo -e "\nPOST INSTALLATION COMPLETE"
