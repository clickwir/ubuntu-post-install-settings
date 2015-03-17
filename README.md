# ubuntu-post-install-settings
Post install settings for Ubuntu installs

This is basically a combination of 2 other scripts, into my own script for running after an Ubuntu install.

The 2 scripts descriptions are as follows:

UK GOV InfoSec
This script provides a basic way of configuring a single Ubuntu machine in accordance
with the attached End User Device guidance. This script contains sugegstions only and
should be customised for individual user needs. In particular it will likely not scale
to large deployments; in those scenarios a purpose-built tool should handle the roll-
out and deployment of these devices. SCM tools, preseed scripts and automated technology
such as PXE boot scripts should be used instead.
https://www.gov.uk/government/uploads/system/uploads/attachment_data/file/413162/install.sh.txt

SSH Securer
https://github.com/mcronce/ssh-securer
Which got it's start here: https://stribika.github.io/2015/01/04/secure-secure-shell.html

Also includes some of the basic apps I first install along with removing the logout, restart and shutdown confirmation dialogs.
