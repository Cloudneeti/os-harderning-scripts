#!/bin/bash

: '
#SYNOPSIS
    Quick win script for remediation of Ubuntu baseline misconfigurations.
.DESCRIPTION
    This script will remediate all possible OS baseline misconfigurations for Ubuntu 18.04 based Virtual machines.

.NOTES

    Copyright (c) Cloudneeti. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 1.0
    # PREREQUISITE

.EXAMPLE
    Command to execute : bash CIS_Ubuntu18_04_Benchmark_v1_0_0_Remediation.sh
.INPUTS

.OUTPUTS
    None
'

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'

success=0
fail=0

############################################################################################################################
###########################################################################################################################

##Category 1.1 Initial Setup - Filesystem Configuration
echo
echo -e "${BLUE}1.1 Initial Setup - Filesystem Configuration${NC}"

# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled
echo
echo -e "${RED}1.1.1.1${NC} Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs | grep "^install /bin/true$" || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^cramfs\s" && rmmod cramfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of cramfs filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of cramfs filesystems is disabled"
  fail=$((fail + 1))
fi

# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled
echo
echo -e "${RED}1.1.1.2${NC} Ensure mounting of freevxfs filesystems is disabled"
modprobe -n -v freevxfs | grep "^install /bin/true$" || echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^freevxfs\s" && rmmod freevxfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of freevxfs filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of freevxfs filesystems is disabled"
  fail=$((fail + 1))
fi

# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled
echo
echo -e "${RED}1.1.1.3${NC} Ensure mounting of jffs2 filesystems is disabled"
modprobe -n -v jffs2 | grep "^install /bin/true$" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^jffs2\s" && rmmod jffs2
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of jffs2 filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of jffs2 filesystems is disabled"
  fail=$((fail + 1))
fi

# 1.1.1.4 Ensure mounting of hfs filesystems is disabled
echo
echo -e "${RED}1.1.1.4${NC} Ensure mounting of hfs filesystems is disabled"
modprobe -n -v hfs | grep "^install /bin/true$" || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^hfs\s" && rmmod hfs
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfs filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfs filesystems is disabled"
  fail=$((fail + 1))
fi

# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled
echo
echo -e "${RED}1.1.1.5${NC} Ensure mounting of hfsplus filesystems is disabled"
modprobe -n -v hfsplus | grep "^install /bin/true$" || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^hfsplus\s" && rmmod hfsplus
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfsplus filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfsplus filesystems is disabled"
  fail=$((fail + 1))
fi

# 1.1.1.6 Ensure mounting of udf filesystems is disabled
echo
echo -e "${RED}1.1.1.6${NC} Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf | grep "^install /bin/true$" || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^udf\s" && rmmod udf
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of udf filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of udf filesystems is disabled"
  fail=$((fail + 1))
fi

# 1.1.20 Ensure sticky bit is set on all world-writable directories
echo
echo -e "${RED}1.1.20${NC} Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure sticky bit is set on all world-writable directories"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure sticky bit is set on all world-writable directories"
  fail=$((fail + 1))
fi

# 1.1.21 Disable Automounting
echo
echo -e "${RED}1.1.21${NC} Disable Automounting"
systemctl disable autofs.service
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Disable Automounting"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Disable Automounting"
  fail=$((fail + 1))
fi
############################################################################################################################

##Category 1.3 Initial Setup - Filesystem Integrity Checking
echo
echo -e "${BLUE} Initial Setup - Filesystem Integrity Checking${NC}"

# 1.3.1 Ensure AIDE is installed
echo
echo -e "${RED}1.3.1 ${NC} Ensure AIDE is installed"
apt-get install aide aide-common -y
#aideinit && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure AIDE is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure AIDE is installed"
  fail=$((fail + 1))
fi

# 1.3.2 Ensure filesystem integrity is regularly checked
echo
echo -e "${RED}1.3.2${NC} Ensure filesystem integrity is regularly checked"
crontab -u root -e
egrep -q "^(\s*)aide\s+\S+(\s*#.*)?\s*$" /etc/crontab && sed -ri "s/^(\s*)aide\s+\S+(\s*#.*)?\s*$/\10 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check\2/" /etc/crontab || echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /etc/crontab
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure filesystem integrity is regularly checked"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure filesystem integrity is regularly checked"
  fail=$((fail + 1))
fi


###########################################################################################################################

##Category 1.4 Initial Setup - Secure Boot Settings
echo
echo -e "${BLUE} Initial Setup - Secure Boot Settings${NC}"

# 1.4.1 Ensure permissions on bootloader config are configured
echo
echo -e "${RED}1.4.1${NC} Ensure permissions on bootloader config are configured"
chown root:root /boot/grub/grub.cfg && chmod og-rwx /boot/grub/grub.cfg && chown root:root /boot/grub/user.cfg && chmod og-rwx /boot/grub/user.cfg
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on bootloader config are configured"
  fail=$((fail + 1))
fi

# 1.4.3 Ensure authentication required for single user mode
echo
echo -e "${RED}1.4.3${NC} Ensure authentication required for single user mode"
passwd root
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure authentication required for single user mode"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure authentication required for single user mode"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 1.5 Initial Setup - Additional Process Hardening
echo
echo -e "${BLUE} Initial Setup - Additional Process Hardening${NC}"


# 1.5.3 Ensure address space layout randomization (ASLR) is enabled
echo
echo -e "${RED}1.5.3${NC} Ensure address space layout randomization (ASLR) is enabled"
egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure address space layout randomization (ASLR) is enabled"
  fail=$((fail + 1))
fi

# 1.5.4 Ensure prelink is disabled
echo
echo -e "${RED}1.5.4${NC} Ensure prelink is disabled"
prelink -ua && apt-get remove prelink
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure authentication required for single user mode"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure authentication required for single user mode"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category Initial Setup - Configure SELinux
echo
echo -e "${BLUE} Initial Setup - Configure SELinux${NC}"

# 1.6.1.1 Ensure SELinux is not disabled in bootloader configuration 
echo
echo -e "${RED}1.6.1.1${NC} Ensure SELinux is not disabled in bootloader configuration"
egrep -q "^(\s*)GRUB_CMDLINE_LINUX_DEFAULT=\s*=\s*\S+(\s*#.*)?\s*$" /etc/default/grub && sed -ri "s/^(\s*)GRUB_CMDLINE_LINUX_DEFAULT=\s*=\s*\S+(\s*#.*)?\s*$/\1GRUB_CMDLINE_LINUX_DEFAULT="quiet"\2/" /etc/default/grub || echo "GRUB_CMDLINE_LINUX_DEFAULT="quiet"" >> /etc/default/grub
egrep -q "^(\s*)GRUB_CMDLINE_LINUX=\s*=\s*\S+(\s*#.*)?\s*$" /etc/default/grub && sed -ri "s/^(\s*)GRUB_CMDLINE_LINUX=\s*=\s*\S+(\s*#.*)?\s*$/\1GRUB_CMDLINE_LINUX=""\2/" /etc/default/grub || echo "GRUB_CMDLINE_LINUX=""" >> /etc/default/grub
update-grub
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SELinux is not disabled in bootloader configuration"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SELinux is not disabled in bootloader configuration"
  fail=$((fail + 1))
fi

# 1.6.1.2 Ensure the SELinux state is enforcing
echo
echo -e "${RED}1.6.1.2${NC} Ensure the SELinux state is enforcing"
egrep -q "^(\s*)SELINUX=\s*=\s*\S+(\s*#.*)?\s*$" /etc/selinux/config && sed -ri "s/^(\s*)SELINUX=\s*=\s*\S+(\s*#.*)?\s*$/\1SELINUX=enforcing\2/" /etc/selinux/config || echo "SELINUX=enforcing" >> /etc/selinux/config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure the SELinux state is enforcing"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the SELinux state is enforcing"
  fail=$((fail + 1))
fi

# 1.6.1.3 Ensure SELinux policy is configured
echo
echo -e "${RED}1.6.1.3${NC} Ensure SELinux policy is configured"
egrep -q "^(\s*)SELINUXTYPE=\s*=\s*\S+(\s*#.*)?\s*$" /etc/selinux/config && sed -ri "s/^(\s*)SELINUXTYPE=\s*=\s*\S+(\s*#.*)?\s*$/\SELINUXTYPE=ubuntu\2/" /etc/selinux/config || echo "SELINUXTYPE=ubuntu" >> /etc/selinux/config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SELinux policy is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SELinux policy is configured"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 1.7 Initial Setup - Warning Banners
echo
echo -e "${BLUE} 1.7 Initial Setup - Warning Banners${NC}"
#Ensure message of the day is configured properly
echo
echo -e "${RED}1.7.1.1${NC} Ensure message of the day is configured properly"
sed -ri 's/(\\v|\\r|\\m|\\s)//g' /etc/motd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure message of the day is configured properly"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure message of the day is configured properly"
  fail=$((fail + 1))
fi

# 1.7.1.2 Ensure local login warning banner is configured properly 
echo
echo -e "${RED}1.7.1.2${NC} Ensure local login warning banner is configured properly"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure local login warning banner is configured properly"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure local login warning banner is configured properly"
  fail=$((fail + 1))
fi

# 1.7.1.3 Ensure remote login warning banner is configured properly
echo
echo -e "${RED}1.7.1.3${NC} Ensure remote login warning banner is configured properly"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure remote login warning banner is configured properly"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure remote login warning banner is configured properly"
  fail=$((fail + 1))
fi

# 1.7.1.4 Ensure permissions on /etc/motd are configured
echo
echo -e "${RED}1.7.1.4${NC} Ensure permissions on /etc/motd are configured"
chown root:root /etc/motd && chmod 644 /etc/motd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/motd are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/motd are configured"
  fail=$((fail + 1))
fi

# 1.7.1.5 Ensure permissions on /etc/issue are configured
echo
echo -e "${RED}1.7.1.5${NC} Ensure permissions on /etc/issue are configured"
chown root:root /etc/issue
chmod 644 /etc/issue
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/issue are configured"
  fail=$((fail + 1))
fi

# 1.7.1.6 Ensure permissions on /etc/issue.net are configured
echo
echo -e "${RED}1.7.1.6${NC} Ensure permissions on /etc/issue.net are configured"
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue.net are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/issue.net are configured"
  fail=$((fail + 1))
fi

#Ensure updates, patches, and additional security software are installed
echo
echo -e "${RED}1.8${NC} Ensure updates, patches, and additional security software are installed"
apt-get upgrade --security
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure updates, patches, and additional security software are installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure updates, patches, and additional security software are installed"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 2.1 Services - inetd Services
echo
echo -e "${BLUE}2.1 Services - inetd Services${NC}"

# 2.1.10 Ensure xinetd is not enabled
echo
echo -e "${RED}2.1.10${NC} Ensure xinetd is not enabled"
systemctl disable xinetd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure xinetd is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure xinetd is not enabled"
  fail=$((fail + 1))
fi

# 2.1.11 Ensure openbsd-inetd is not installed
echo
echo -e "${RED}2.1.11${NC} Ensure openbsd-inetd is not installed"
apt-get remove openbsd-inetd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure openbsd-inetd is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure openbsd-inetd is not installed"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 2.2 Services - Special Purpose Services
echo
echo -e "${BLUE}2.2 Services - Special Purpose Services${NC}"

#Ensure time synchronization is in use
echo
echo -e "${RED}2.2.1.1${NC} Ensure time synchronization is in use"
apt-get install ntp -y && apt-get install chrony -y
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure time synchronization is in use"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure time synchronization is in use"
  fail=$((fail + 1))
fi

#Ensure ntp is configured
echo
echo -e "${RED}2.2.1.2${NC} Ensure ntp is configured"
if rpm -q ntp >/dev/null; then
    egrep -q "^\s*restrict(\s+-4)?\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict(\s+-4)?\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict\2 default kod nomodify notrap nopeer noquery\4/" /etc/ntp.conf || echo "restrict default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf 
    egrep -q "^\s*restrict\s+-6\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict\s+-6\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict -6 default kod nomodify notrap nopeer noquery\3/" /etc/ntp.conf || echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf 
    egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/sysconfig/ntpd && sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u ntp:ntp\"\3/ }' /etc/sysconfig/ntpd && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u ntp:ntp\3\"\4/" /etc/sysconfig/ntpd || echo "OPTIONS=\"-u ntp:ntp\"" >> /etc/sysconfig/ntpd
fi
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure ntp is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure ntp is configured"
  fail=$((fail + 1))
fi

#Ensure chrony is configured
echo
echo -e "${RED}2.2.1.3${NC} Ensure chrony is configured"
if rpm -q chrony >/dev/null; then
    egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/sysconfig/chronyd && sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u chrony\"\3/ }' /etc/sysconfig/chronyd && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u chrony\3\"\4/" /etc/sysconfig/chronyd || echo "OPTIONS=\"-u chrony\"" >> /etc/sysconfig/chronyd
fi
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure chrony is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure chrony is configured"
  fail=$((fail + 1))
fi

#Ensure X Window System is not installed
echo
echo -e "${RED}2.2.2${NC} Ensure X Window System is not installed"
apt-get remove xserver-xorg*
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure X Window System is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure X Window System is not installed"
  fail=$((fail + 1))
fi

# 2.2.3 Ensure Avahi Server is not enabled
echo
echo -e "${RED}2.2.3${NC} Ensure Avahi Server is not enabled"
systemctl disable avahi-daemon
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Avahi Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Avahi Server is not enabled"
  fail=$((fail + 1))
fi

# 2.2.4 Ensure CUPS is not enabled
echo
echo -e "${RED}2.2.4${NC} Ensure CUPS is not enabled"
systemctl disable cups
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure CUPS is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure CUPS is not enabled"
  fail=$((fail + 1))
fi

# 2.2.5 Ensure DHCP Server is not enabled
echo
echo -e "${RED}2.2.5${NC} Ensure DHCP Server is not enabled"
systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DHCP Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DHCP Server is not enabled"
  fail=$((fail + 1))
fi

#Ensure LDAP server is not enabled
echo
echo -e "${RED}2.2.6${NC} Ensure LDAP server is not enabled"
systemctl disable slapd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure LDAP server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure LDAP server is not enabled"
  fail=$((fail + 1))
fi

# 2.2.8 Ensure DNS Server is not enabled
echo
echo -e "${RED}2.2.8${NC} Ensure DNS Server is not enabled"
systemctl disable bind9
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DNS Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DNS Server is not enabled"
  fail=$((fail + 1))
fi

# 2.2.11 Ensure IMAP and POP3 server is not enabled (Ensure email services are not enabled)
echo
echo -e "${RED}2.2.11${NC} Ensure IMAP and POP3 server is not enabled"
systemctl disable dovecot
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IMAP and POP3 server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IMAP and POP3 server is not enabled"
  fail=$((fail + 1))
fi

#2.2.12 Ensure Samba is not enabled
echo
echo -e "${RED}2.2.12${NC} Ensure Samba is not enabled"
systemctl disable smb
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Samba is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Samba is not enabled"
  fail=$((fail + 1))
fi

#2.2.14 Ensure SNMP Server is not enabled
echo
echo -e "${RED}2.2.14${NC} Ensure SNMP Server is not enabled"
systemctl disable snmpd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SNMP Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SNMP Server is not enabled"
  fail=$((fail + 1))
fi

#2.2.16 Ensure rsync service is not enabled
echo
echo -e "${RED}2.2.16${NC} Ensure rsync service is not enabled"
systemctl disable rsyncd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsync service is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsync service is not enabled"
  fail=$((fail + 1))
fi

#2.2.17 Ensure NIS Server is not enabled
echo
echo -e "${RED}2.2.17${NC} Ensure NIS Server is not enabled"
systemctl disable nis
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NIS Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NIS Server is not enabled"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 2.3 Services - Service Clients
echo
echo -e "${BLUE}2.3 Services - Service Clients${NC}"

# 2.3.1 Ensure NIS Client is not installed
echo
echo -e "${RED}2.3.1${NC} Ensure NIS Client is not installed"
apt-get remove nis
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NIS Client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NIS Client is not installed"
  fail=$((fail + 1))
fi

# 2.3.2 Ensure rsh client is not installed
echo
echo -e "${RED}2.3.2${NC} Ensure rsh client is not installed"
apt-get remove rsh-client rsh-redone-client
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsh client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh client is not installed"
  fail=$((fail + 1))
fi

# 2.3.4 Ensure telnet client is not installed
echo
echo -e "${RED}2.3.4${NC} Ensure telnet client is not installed"
apt-get remove telnet -y
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure telnet client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure telnet client is not installed"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 3.1 Network Configuration - Network Parameters (Host Only)
echo
echo -e "${BLUE}3.1 Network Configuration - Network Parameters (Host Only)${NC}"

# 3.1.1 Ensure IP forwarding is disabled
echo
echo -e "${RED}3.1.1${NC} Ensure IP forwarding is disabled"
egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0 && sysctl -w net.ipv4.route.flush=1
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IP forwarding is disabled"
  fail=$((fail + 1))
fi

#Ensure packet redirect sending is disabled
echo
echo -e "${RED}3.1.2${NC} Ensure packet redirect sending is disabled"
egrep -q "^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure packet redirect sending is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure packet redirect sending is disabled"
  fail=$((fail + 1))
fi


###########################################################################################################################

##Category 3.2 Network Configuration - Network Parameters (Host and Router)
echo
echo -e "${BLUE}3.2 Network Configuration - Network Parameters (Host and Router)${NC}"

#Ensure source routed packets are not accepted
echo
echo -e "${RED}3.2.1${NC} Ensure source routed packets are not accepted"
egrep -q "^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Ensure source routed packets are not accepted"
success=$((success + 1))

#Ensure ICMP redirects are not accepted
echo
echo -e "${RED}3.2.2${NC} Ensure ICMP redirects are not accepted"
egrep -q "^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure ICMP redirects are not accepted"
success=$((success + 1))

#Ensure secure ICMP redirects are not accepted
echo
echo -e "${RED}3.2.3${NC} Ensure secure ICMP redirects are not accepted"
egrep -q "^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.secure_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.secure_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure secure ICMP redirects are not accepted"
success=$((success + 1))

#Ensure suspicious packets are logged
echo
echo -e "${RED}3.2.4${NC} Ensure suspicious packets are logged"
egrep -q "^(\s*)net.ipv4.conf.all.log_martians\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.log_martians\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.log_martians = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.log_martians\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.log_martians\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.log_martians = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure suspicious packets are logged"
success=$((success + 1))

#Ensure broadcast ICMP requests are ignored
echo
echo -e "${RED}3.2.5${NC} Ensure broadcast ICMP requests are ignored"
egrep -q "^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_echo_ignore_broadcasts = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Ensure broadcast ICMP requests are ignored"
success=$((success + 1))

#Ensure bogus ICMP responses are ignored
echo
echo -e "${RED}3.2.6${NC} Ensure bogus ICMP responses are ignored"
egrep -q "^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_ignore_bogus_error_responses = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Ensure bogus ICMP responses are ignored"
success=$((success + 1))

#Ensure Reverse Path Filtering is enabled
echo
echo -e "${RED}3.2.7${NC} Ensure Reverse Path Filtering is enabled"
egrep -q "^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Ensure Reverse Path Filtering is enabled"
success=$((success + 1))

#Ensure TCP SYN Cookies is enabled
echo
echo -e "${RED}3.2.8${NC} Ensure TCP SYN Cookies is enabled"
egrep -q "^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.tcp_syncookies = 1\2/" /etc/sysctl.conf || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Ensure TCP SYN Cookies is enabled"
success=$((success + 1))

############################################################################################################################

##Category 3.3 Network Configuration - IPv6
echo
echo -e "${BLUE}3.3 Network Configuration - IPv6${NC}"

#Ensure IPv6 router advertisements are not accepted
echo
echo -e "${RED}3.3.1${NC} Ensure IPv6 router advertisements are not accepted"
egrep -q "^(\s*net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure IPv6 router advertisements are not accepted"
success=$((success + 1))

#Ensure IPv6 redirects are not accepted
echo
echo -e "${RED}3.3.2${NC} Ensure IPv6 redirects are not accepted"
egrep -q "^(\s*net.ipv6.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv6.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure IPv6 redirects are not accepted"
success=$((success + 1))

#Ensure IPv6 is disabled
echo
echo -e "${RED}3.3.3${NC} Ensure IPv6 is disabled"
egrep -q "^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\S+(\s*#.*)?\s*$" /etc/default/grub && sed -ri "s/^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\S+(\s*#.*)?\s*$/\1GRUB_CMDLINE_LINUX=\"ipv6.disable=1\"\2/" /etc/default/grub || echo "GRUB_CMDLINE_LINUX=\"ipv6.disable=1\"" >> /etc/default/grub
update-grub
echo -e "${GREEN}Remediated:${NC} Ensure IPv6 is disabled"
success=$((success + 1))

############################################################################################################################

##Category 3.4 Network Configuration - TCP Wrappers
echo
echo -e "${BLUE}3.4 Network Configuration - TCP Wrappers${NC}"

#Ensure TCP Wrappers is installed
echo
echo -e "${RED}3.4.1${NC} Ensure TCP Wrappers is installed"
apt-get install tcpd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TCP Wrappers is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TCP Wrappers is installed"
  fail=$((fail + 1))
fi

#Ensure /etc/hosts.deny is configured
echo
echo -e "${RED}3.4.3${NC} Ensure /etc/hosts.deny is configured"
echo "ALL: ALL" >> /etc/hosts.deny
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure /etc/hosts.deny is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure /etc/hosts.deny is configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/hosts.allow are configured
echo
echo -e "${RED}3.4.4${NC} Ensure permissions on /etc/hosts.allow are configured"
chown root:root /etc/hosts.allow && chmod 644 /etc/hosts.allow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/hosts.allow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/hosts.allow are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/hosts.deny are configured
echo
echo -e "${RED}3.4.5${NC} Ensure permissions on /etc/hosts.deny are configured"
chown root:root /etc/hosts.deny && chmod 644 /etc/hosts.deny
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/hosts.deny are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/hosts.deny are configured"
  fail=$((fail + 1))
fi
############################################################################################################################

##Category 3.5 Network Configuration - Uncommon Network Protocols
echo
echo -e "${BLUE}3.5 Network Configuration - Uncommon Network Protocols${NC}"

#Ensure DCCP is disabled
echo
echo -e "${RED}3.5.1${NC} Ensure DCCP is disabled"
modprobe -n -v dccp | grep "^install /bin/true$" || echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^dccp\s" && rmmod dccp
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DCCP is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DCCP is disabled"
  fail=$((fail + 1))
fi

#Ensure SCTP is disabled
echo
echo -e "${RED}3.5.2${NC} Ensure SCTP is disabled"
modprobe -n -v sctp | grep "^install /bin/true$" || echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^sctp\s" && rmmod sctp
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SCTP is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SCTP is disabled"
  fail=$((fail + 1))
fi

#Ensure RDS is disabled
echo
echo -e "${RED}3.5.3${NC} Ensure RDS is disabled"
modprobe -n -v rds | grep "^install /bin/true$" || echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^rds\s" && rmmod rds
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure RDS is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure RDS is disabled"
  fail=$((fail + 1))
fi

#Ensure TIPC is disabled
echo
echo -e "${RED}3.5.4${NC} Ensure TIPC is disabled"
modprobe -n -v tipc | grep "^install /bin/true$" || echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^tipc\s" && rmmod tipc
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TIPC is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TIPC is disabled"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 3.6 Network Configuration - Firewall Configuration
echo
echo -e "${BLUE}3.6 Network Configuration - Firewall Configuration${NC}"

# 3.6.1 Ensure iptables is installed
echo
echo -e "${RED}3.6.1${NC} Ensure iptables is installed"
apt-get install iptables
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure iptables is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure iptables is installed"
  fail=$((fail + 1))
fi

# 3.6.2 Ensure default deny firewall policy
echo
echo -e "${RED}3.6.2${NC} Ensure default deny firewall policy"
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure default deny firewall policy"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure default deny firewall policy"
  fail=$((fail + 1))
fi

# 3.6.3 Ensure loopback traffic is configured
echo
echo -e "${RED}3.6.3${NC} Ensure loopback traffic is configured"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure loopback traffic is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure loopback traffic is configured"
  fail=$((fail + 1))
fi

#Ensure outbound and established connections are configured
echo
echo -e "${RED}3.6.4${NC} Ensure outbound and established connections are configured"
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
echo -e "${GREEN}Remediated:${NC} Ensure outbound and established connections are configured"
success=$((success + 1))

############################################################################################################################

##Category 4.1 Logging and Auditing - Configure System Accounting (auditd)
echo
echo -e "${BLUE}4.1 Logging and Auditing - Configure System Accounting (auditd)${NC}"

# 4.1.1.2 Ensure system is disabled when audit logs are full
echo
echo -e "${RED}4.1.1.2${NC} Ensure system is disabled when audit logs are full"
apt-get install auditd -y
egrep -q "^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1space_left_action = email\2/" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf
egrep -q "^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$/\1action_mail_acct = root\2/" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf
egrep -q "^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1admin_space_left_action = halt\2/" /etc/audit/auditd.conf || echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf
echo -e "${GREEN}Remediated:${NC} Ensure system is disabled when audit logs are full"
success=$((success + 1))

# 4.1.1.3 Ensure audit logs are not automatically deleted
echo
echo -e "${RED}4.1.1.3${NC} Ensure audit logs are not automatically deleted"
egrep -q "^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$/\1max_log_file_action = keep_logs\2/" /etc/audit/auditd.conf || echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure audit logs are not automatically deleted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure audit logs are not automatically deleted"
  fail=$((fail + 1))
fi

# 4.1.2 Ensure auditd service is enabled
echo
echo -e "${RED}4.1.2${NC} Ensure auditd service is enabled"
systemctl enable auditd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure auditd service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure auditd service is enabled"
  fail=$((fail + 1))
fi

# 4.1.3 Ensure auditing for processes that start prior to auditd is enabled
echo
echo -e "${RED}4.1.3${NC} Ensure auditing for processes that start prior to auditd is enabled"
egrep -q "^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\S+(\s*#.*)?\s*$" /etc/default/grub && sed -ri "s/^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\S+(\s*#.*)?\s*$/\1GRUB_CMDLINE_LINUX = \"audit=1\"\2/" /etc/default/grub || echo "GRUB_CMDLINE_LINUX = \"audit=1\"" >> /etc/default/grub
update-grub
echo -e "${GREEN}Remediated:${NC} Ensure auditing for processes that start prior to auditd is enabled"
success=$((success + 1))

# 4.1.4 Ensure events that modify date and time information are collected
echo
echo -e "${RED}4.1.4${NC} Ensure events that modify date and time information are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-S\s+stime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+clock_settime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/localtime\s+-p\s+wa\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+clock_settime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure events that modify date and time information are collected"
success=$((success + 1))

# 4.1.5 Ensure events that modify user/group information are collected
echo
echo -e "${RED}4.1.5${NC} Ensure events that modify user/group information are collected"
egrep "^-w\s+/etc/group\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/passwd\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/gshadow\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/shadow\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/security/opasswd\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure events that modify user/group information are collected"
success=$((success + 1))

# 4.1.6 Ensure events that modify the system's network environment are collected
echo
echo -e "${RED}4.1.6${NC} Ensure events that modify the system's network environment are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/issue\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/issue.net\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/hosts\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/sysconfig/network\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's network environment are collected"
success=$((success + 1))

# 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected
echo
echo -e "${RED}4.1.7${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
egrep "^-w\s+/etc/selinux/\s+-p\s+wa\s+-k\s+MAC-policy\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
success=$((success + 1))

# 4.1.8 Ensure login and logout events are collected
echo
echo -e "${RED}4.1.8${NC} Ensure login and logout events are collected"
egrep "^-w\s+/var/run/faillock/\s+-p\s+wa\s+-k\s+logins\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure login and logout events are collected"
success=$((success + 1))

# 4.1.9 Ensure session initiation information is collected
echo
echo -e "${RED}4.1.9${NC} Ensure session initiation information is collected"
egrep "^-w\s+/var/run/utmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/var/log/wtmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/var/log/btmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure session initiation information is collected"
success=$((success + 1))

# 4.1.10 Ensure discretionary access control permission modification events are collected
echo
echo -e "${RED}4.1.10${NC} Ensure discretionary access control permission modification events are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure discretionary access control permission modification events are collected"
success=$((success + 1))

# 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected
echo
echo -e "${RED}4.1.11${NC} Ensure unsuccessful unauthorized file access attempts are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure unsuccessful unauthorized file access attempts are collected"
success=$((success + 1))

# 4.1.12 Ensure use of privileged commands is collected
echo
echo -e "${RED}4.1.12${NC} Ensure use of privileged commands is collected"
for file in `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f`; do
    egrep -q "^\s*-a\s+(always,exit|exit,always)\s+-F\s+path=$file\s+-F\s+perm=x\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged\s*(#.*)?$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=$file -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/audit.rules;
done
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure use of privileged commands is collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure use of privileged commands is collected"
  fail=$((fail + 1))
fi

# 4.1.13 Ensure successful file system mounts are collected
echo
echo -e "${RED}4.1.13${NC} Ensure successful file system mounts are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure successful file system mounts are collected"
success=$((success + 1))

# 4.1.14 Ensure file deletion events by users are collected
echo
echo -e "${RED}4.1.14${NC} Ensure file deletion events by users are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure file deletion events by users are collected"
success=$((success + 1))

# 4.1.15 Ensure changes to system administration scope (sudoers) is collected
echo
echo -e "${RED}4.1.15${NC} Ensure changes to system administration scope (sudoers) is collected"
egrep "^-w\s+/etc/sudoers\s+-p\s+wa\s+-k\s+scope\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/sudoers.d\s+-p\s+wa\s+-k\s+scope\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure changes to system administration scope (sudoers) is collected"
success=$((success + 1))

# 4.1.16 Ensure system administrator actions (sudolog) are collected
echo
echo -e "${RED}4.1.16${NC} Ensure system administrator actions (sudolog) are collected"
egrep "^-w\s+/var/log/sudo.log\s+-p\s+wa\s+-k\s+actions\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure system administrator actions (sudolog) are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure system administrator actions (sudolog) are collected"
  fail=$((fail + 1))
fi

# 4.1.17 Ensure kernel module loading and unloading is collected
echo
echo -e "${RED}4.1.17${NC} Ensure kernel module loading and unloading is collected"
egrep "^-w\s+/sbin/insmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/sbin/rmmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/sbin/modprobe\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' || egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure kernel module loading and unloading is collected"
success=$((success + 1))

# 4.1.18 Ensure the audit configuration is immutable
echo
echo -e "${RED}4.1.18${NC} Ensure the audit configuration is immutable"
grep "-e 2" /etc/audit/audit.rules || echo "-e 2" >> /etc/audit/audit.rules
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure the audit configuration is immutable"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the audit configuration is immutable"
  fail=$((fail + 1))
fi
 
############################################################################################################################

##Category 4.2 Logging and Auditing - Configure rsyslog
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure rsyslog${NC}"

# 4.2.1.1 Ensure rsyslog Service is enabled
echo
echo -e "${RED}4.2.1.1${NC} Ensure rsyslog Service is enabled"
apt-get install rsyslog -y && systemctl enable rsyslog
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog Service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog Service is enabled"
  fail=$((fail + 1))
fi

# 4.2.1.3 Ensure rsyslog default file permissions configured
echo
echo -e "${RED}4.2.1.3${NC} Ensure rsyslog default file permissions configured"
grep "$FileCreateMode 0640" /etc/rsyslog.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.conf
grep "$FileCreateMode 0640" /etc/rsyslog.d/*.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.d/*.conf
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog default file permissions configured"
success=$((success + 1))

# 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts
echo
echo -e "${RED}4.2.1.5${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"
sed -i -e 's/#$ModLoad imtcp.so/$ModLoad imtcp.so/g' /etc/rsyslog.conf
grep "$ModLoad imtcp.so" /etc/rsyslog.conf || echo "$""ModLoad imtcp.so" >> /etc/rsyslog.conf
sed -i -e 's/#$InputTCPServerRun 514/$InputTCPServerRun 514/g' /etc/rsyslog.conf
grep "$InputTCPServerRun 514" /etc/rsyslog.conf || echo "$""InputTCPServerRun 514" >> /etc/rsyslog.conf
echo -e "${GREEN}Remediated:${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"
success=$((success + 1))

#Ensure syslog-ng service is enabled
echo
echo -e "${RED}4.2.2.1${NC} Ensure syslog-ng service is enabled"
apt-get install syslog-ng && update-rc.d syslog-ng enable
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure syslog-ng service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure syslog-ng service is enabled"
  fail=$((fail + 1))
fi

#Ensure permissions on all logfiles are configured
echo
echo -e "${RED}4.2.4${NC} Ensure permissions on all logfiles are configured"
find /var/log -type f -exec chmod g-wx,o-rwx {} +
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on all logfiles are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on all logfiles are configured"
  fail=$((fail + 1))
fi



#Ensure rsyslog or syslog-ng is installed
echo
echo -e "${RED}4.2.3${NC} Ensure rsyslog or syslog-ng is installed"
apt-get install rsyslog && apt-get install syslog-ng
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog or syslog-ng is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog or syslog-ng is installed"
  fail=$((fail + 1))
fi

#Ensure permissions on all logfiles are configured
echo
echo -e "${RED}4.2.4${NC} Ensure permissions on all logfiles are configured"
find /var/log -type f -exec chmod g-wx,o-rwx {} +
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on all logfiles are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on all logfiles are configured"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 5.1 Access, Authentication and Authorization - Configure cron
echo
echo -e "${BLUE}5.1 Access, Authentication and Authorization - Configure cron${NC}"

# 5.1.1 Ensure cron daemon is enabled
echo
echo -e "${RED}5.1.1${NC} Ensure cron daemon is enabled"
systemctl enable cron
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure cron daemon is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure cron daemon is enabled"
  fail=$((fail + 1))
fi

# 5.1.2 Ensure permissions on /etc/crontab are configured
echo
echo -e "${RED}5.1.2${NC} Ensure permissions on /etc/crontab are configured"
chown root:root /etc/crontab && chmod og-rwx /etc/crontab
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/crontab are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/crontab are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/cron.hourly are configured
echo
echo -e "${RED}5.1.3${NC} Ensure permissions on /etc/cron.hourly are configured"
chown root:root /etc/cron.hourly && chmod og-rwx /etc/cron.hourly
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.hourly are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.hourly are configured"
  fail=$((fail + 1))
fi

# 5.1.4 Ensure permissions on /etc/cron.daily are configured
echo
echo -e "${RED}5.1.4${NC} Ensure permissions on /etc/cron.daily are configured"
chown root:root /etc/cron.daily && chmod og-rwx /etc/cron.daily
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.daily are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.daily are configured"
  fail=$((fail + 1))
fi

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured
echo
echo -e "${RED}5.1.5${NC} Ensure permissions on /etc/cron.weekly are configured"
chown root:root /etc/cron.weekly && chmod og-rwx /etc/cron.weekly
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.weekly are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.weekly are configured"
  fail=$((fail + 1))
fi

# 5.1.6 Ensure permissions on /etc/cron.monthly are configured
echo
echo -e "${RED}5.1.6${NC} Ensure permissions on /etc/cron.monthly are configured"
chown root:root /etc/cron.monthly && chmod og-rwx /etc/cron.monthly
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.monthly are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.monthly are configured"
  fail=$((fail + 1))
fi

# 5.1.7 Ensure permissions on /etc/cron.d are configured
echo
echo -e "${RED}5.1.7${NC} Ensure permissions on /etc/cron.d are configured"
chown root:root /etc/cron.d && chmod og-rwx /etc/cron.d
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.d are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.d are configured"
  fail=$((fail + 1))
fi

# 5.1.8 Ensure at/cron is restricted to authorized users
echo
echo -e "${RED}5.1.8${NC} Ensure at/cron is restricted to authorized users"
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
echo -e "${GREEN}Remediated:${NC} Ensure at/cron is restricted to authorized users"
success=$((success + 1))

############################################################################################################################

##Category 5.2 Access, Authentication and Authorization - SSH Server Configuration
echo
echo -e "${BLUE}5.2 Access, Authentication and Authorization - SSH Server Configuration${NC}"

#Ensure permissions on /etc/ssh/sshd_config are configured
echo
echo -e "${RED}5.2.1${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
chown root:root /etc/ssh/sshd_config && chmod og-rwx /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
  fail=$((fail + 1))
fi

# 5.2.2 Ensure SSH Protocol is set to 2
echo
echo -e "${RED}5.2.2${NC} Ensure SSH Protocol is set to 2"
egrep -q "^(\s*)Protocol\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Protocol\s+\S+(\s*#.*)?\s*$/\1Protocol 2\2/" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Protocol is set to 2"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Protocol is set to 2"
  fail=$((fail + 1))
fi

#Ensure SSH LogLevel is set to INFO
echo
echo -e "${RED}5.2.3${NC} Ensure SSH LogLevel is set to INFO"
egrep -q "^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$/\1LogLevel INFO\2/" /etc/ssh/sshd_config || echo "LogLevel INFO" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH LogLevel is set to INFO"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LogLevel is set to INFO"
  fail=$((fail + 1))
fi

#Ensure SSH X11 forwarding is disabled
echo
echo -e "${RED}5.2.4${NC} Ensure SSH X11 forwarding is disabled"
egrep -q "^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$/\1X11Forwarding no\2/" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH X11 forwarding is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH X11 forwarding is disabled"
  fail=$((fail + 1))
fi

#Ensure SSH MaxAuthTries is set to 4 or less
echo
echo -e "${RED}5.2.5${NC} Ensure SSH MaxAuthTries is set to 4 or less"
egrep -q "^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$/\1MaxAuthTries 4\2/" /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  fail=$((fail + 1))
fi

# 5.2.6 Ensure SSH IgnoreRhosts is enabled
echo
echo -e "${RED}5.2.6${NC} Ensure SSH IgnoreRhosts is enabled"
egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH IgnoreRhosts is enabled"
  fail=$((fail + 1))
fi

# 5.2.7 Ensure SSH HostbasedAuthentication is disabled
echo
echo -e "${RED}5.2.7${NC} Ensure SSH HostbasedAuthentication is disabled"
egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH HostbasedAuthentication is disabled"
  fail=$((fail + 1))
fi

#Ensure SSH root login is disabled
echo
echo -e "${RED}5.2.8${NC} Ensure SSH root login is disabled"
egrep -q "^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$/\1PermitRootLogin no\2/" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH root login is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH root login is disabled"
  fail=$((fail + 1))
fi

# 5.2.9 Ensure SSH PermitEmptyPasswords is disabled
echo
echo -e "${RED}5.2.9${NC} Ensure SSH PermitEmptyPasswords is disabled"
egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  fail=$((fail + 1))
fi

# 5.2.10 Ensure SSH PermitUserEnvironment is disabled
echo
echo -e "${RED}5.2.10${NC} Ensure SSH PermitUserEnvironment is disabled"
egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitUserEnvironment is disabled"
  fail=$((fail + 1))
fi

#Ensure only approved MAC algorithms are used
echo
echo -e "${RED}5.2.11${NC} Ensure only approved MAC algorithms are used"
egrep -q "^(\s*)MACs\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MACs\s+\S+(\s*#.*)?\s*$/\1MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\2/" /etc/ssh/sshd_config || echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure only approved MAC algorithms are used"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure only approved MAC algorithms are used"
  fail=$((fail + 1))
fi

#Ensure SSH Idle Timeout Interval is configured
echo
echo -e "${RED}5.2.12${NC} Ensure SSH Idle Timeout Interval is configured"
egrep -q "^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\1ClientAliveInterval 300\2/" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
egrep -q "^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\1ClientAliveCountMax 0\2/" /etc/ssh/sshd_config || echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH Idle Timeout Interval is configured"
success=$((success + 1))

#Ensure SSH LoginGraceTime is set to one minute or less
echo
echo -e "${RED}5.2.13${NC} Ensure SSH LoginGraceTime is set to one minute or less"
egrep -q "^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$/\1LoginGraceTime 60\2/" /etc/ssh/sshd_config || echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  fail=$((fail + 1))
fi

#Ensure SSH warning banner is configured
echo
echo -e "${RED}5.2.15${NC} Ensure SSH warning banner is configured"
egrep -q "^(\s*)Banner\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Banner\s+\S+(\s*#.*)?\s*$/\1Banner /etc/issue.net\2/" /etc/ssh/sshd_config || echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH warning banner is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH warning banner is configured"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 5.3 Access, Authentication and Authorization - Configure PAM
echo
echo -e "${BLUE}5.3 Access, Authentication and Authorization - Configure PAM${NC}"

# 5.3.1 Ensure password creation requirements are configured
echo
echo -e "${RED}5.3.1${NC} Ensure password creation requirements are configured"
egrep -q "^\s*password\s+requisite\s+pam_pwquality.so\s+" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/ { /^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*(\s+try_first_pass)(\s+.*)?$/! s/^(\s*password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1try_first_pass \2/ }' /etc/pam.d/password-auth && sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/ { /^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*(\s+retry=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1retry=3 \2/ }' /etc/pam.d/password-auth && sed -ri 's/(^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*\s+)retry=[0-9]+(\s+.*)?$/\1retry=3\3/' /etc/pam.d/password-auth || echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/password-auth
egrep -q "^\s*password\s+requisite\s+pam_pwquality.so\s+" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/ { /^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*(\s+try_first_pass)(\s+.*)?$/! s/^(\s*password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1try_first_pass \2/ }' /etc/pam.d/system-auth && sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/ { /^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*(\s+retry=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1retry=3 \2/ }' /etc/pam.d/system-auth && sed -ri 's/(^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*\s+)retry=[0-9]+(\s+.*)?$/\1retry=3\3/' /etc/pam.d/system-auth || echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/system-auth
egrep -q "^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$/\minlen=14\2/" /etc/security/pwquality.conf || echo "minlen=14" >> /etc/security/pwquality.conf
egrep -q "^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$/\dcredit=-1\2/" /etc/security/pwquality.conf || echo "dcredit=-1" >> /etc/security/pwquality.conf
egrep -q "^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$/\ucredit=-1\2/" /etc/security/pwquality.conf || echo "ucredit=-1" >> /etc/security/pwquality.conf
egrep -q "^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$/\ocredit=-1\2/" /etc/security/pwquality.conf || echo "ocredit=-1" >> /etc/security/pwquality.conf
egrep -q "^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$/\lcredit=-1\2/" /etc/security/pwquality.conf || echo "lcredit=-1" >> /etc/security/pwquality.conf
echo -e "${GREEN}Remediated:${NC} Ensure password creation requirements are configured"
success=$((success + 1))

# 5.3.3 Ensure password reuse is limited
echo
echo -e "${RED}5.3.3${NC} Ensure password reuse is limited"
egrep -q "^\s*password\s+sufficient\s+pam_unix.so(\s+.*)$" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+remember=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1remember=5 \2/ }' /etc/pam.d/password-auth && sed -ri 's/(^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*\s+)remember=[0-9]+(\s+.*)?$/\1remember=5\3/' /etc/pam.d/password-auth || echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/password-auth
egrep -q "^\s*password\s+sufficient\s+pam_unix.so(\s+.*)$" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+remember=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1remember=5 \2/ }' /etc/pam.d/system-auth && sed -ri 's/(^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*\s+)remember=[0-9]+(\s+.*)?$/\1remember=5\3/' /etc/pam.d/system-auth || echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/system-auth
echo -e "${GREEN}Remediated:${NC} Ensure password reuse is limited"
success=$((success + 1))

# 5.3.4 Ensure password hashing algorithm is SHA-512
echo
echo -e "${RED}5.3.4${NC} Ensure password hashing algorithm is SHA-512"
egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/password-auth || echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/password-auth
egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/system-auth || echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/system-auth
echo -e "${GREEN}Remediated:${NC} Ensure password hashing algorithm is SHA-512"
success=$((success + 1))

############################################################################################################################

##Category 5.4 Access, Authentication and Authorization - User Accounts and Environment
echo
echo -e "${BLUE}5.4 Access, Authentication and Authorization - User Accounts and Environment${NC}"

# 5.4.1.1 Ensure password expiration is 365 days or less
echo
echo -e "${RED}5.4.1.1${NC} Ensure password expiration is 365 days or less"
egrep -q "^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 90\2/" /etc/login.defs || echo "PASS_MAX_DAYS 90" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --maxdays 90
echo -e "${GREEN}Remediated:${NC} Ensure password expiration is 365 days or less"
success=$((success + 1))

# 5.4.1.2 Ensure minimum days between password changes is 7 or more
echo
echo -e "${RED}5.4.1.2${NC} Ensure minimum days between password changes is 7 or more"
egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 7\2/" /etc/login.defs || echo "PASS_MIN_DAYS 7" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --mindays 7
echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is 7 or more"
success=$((success + 1))


# 5.4.1.3 Ensure password expiration warning days is 7 or more
echo
echo -e "${RED}5.4.1.3${NC} Ensure password expiration warning days is 7 or more"
egrep -q "^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$/\PASS_WARN_AGE 7\2/" /etc/login.defs || echo "PASS_WARN_AGE 7" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --warndays 7
echo -e "${GREEN}Remediated:${NC} Ensure password expiration warning days is 7 or more"
success=$((success + 1))

# 5.4.1.4 Ensure inactive password lock is 30 days or less
echo
echo -e "${RED}5.4.1.4${NC} Ensure inactive password lock is 30 days or less"
useradd -D -f 30 && getent passwd | cut -f1 -d ":" | xargs -n1 chage --inactive 30
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure inactive password lock is 30 days or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure inactive password lock is 30 days or less"
  fail=$((fail + 1))
fi

# 5.4.2 Ensure system accounts are non-login
echo
echo -e "${RED}5.4.2${NC} Ensure system accounts are non-login"
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    usermod -L $user
    if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
      usermod -s /usr/sbin/nologin $user
    fi
  fi
done
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure system accounts are non-login"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure system accounts are non-login"
  fail=$((fail + 1))
fi

# 5.4.3 Ensure default group for the root account is GID 0
echo
echo -e "${RED}5.4.3${NC} Ensure default group for the root account is GID 0"
usermod -g 0 root
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure default group for the root account is GID 0"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure default group for the root account is GID 0"
  fail=$((fail + 1))
fi

# 5.4.4 Ensure default user umask is 027 or more restrictive
echo
echo -e "${RED}5.4.4${NC} Ensure default user umask is 027 or more restrictive"
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/bash.bashrc && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/bash.bashrc || echo "umask 077" >> /etc/bash.bashrc
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/profile || echo "umask 077" >> /etc/profile
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/profile.d/*.sh || echo "umask 077" >> /etc/profile.d/*.sh
echo -e "${GREEN}Remediated:${NC} Ensure default user umask is 027 or more restrictive"
success=$((success + 1))

#Ensure default user shell timeout is 900 seconds or less
echo
echo -e "${RED}5.4.5${NC} Ensure default user shell timeout is 900 seconds or less"
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/bash.bashrc && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/bash.bashrc || echo "TMOUT=600" >> /etc/bash.bashrc
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile || echo "TMOUT=600" >> /etc/profile
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile.d/*.sh || echo "TMOUT=600" >> /etc/profile.d/*.sh
echo -e "${GREEN}Remediated:${NC} Ensure default user shell timeout is 900 seconds or less"
success=$((success + 1))

#Ensure access to the su command is restricted
echo
echo -e "${RED}5.6${NC} Ensure access to the su command is restricted"
egrep -q "^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$" /etc/pam.d/su && sed -ri '/^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$/ { /^\s*auth\s+required\s+pam_wheel.so(\s+\S+)*(\s+use_uid)(\s+.*)?$/! s/^(\s*auth\s+required\s+pam_wheel.so)(\s+.*)?$/\1 use_uid\2/ }' /etc/pam.d/su || echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure access to the su command is restricted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure access to the su command is restricted"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"

# 6.1.2 Ensure permissions on /etc/passwd are configured
echo
echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
chown root:root /etc/passwd
chmod 644 /etc/passwd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are configured"
  fail=$((fail + 1))
fi

# 6.1.3 Ensure permissions on /etc/shadow are configured
echo
echo -e "${RED}6.1.3${NC} Ensure permissions on /etc/shadow are configured"
chown root:shadow /etc/shadow && chmod o-rwx,g-wx /etc/shadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow are configured"
  fail=$((fail + 1))
fi

# 6.1.4 Ensure permissions on /etc/group are configured
echo
echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
chown root:root /etc/group
chmod 644 /etc/group
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are configured"
  fail=$((fail + 1))
fi

# 6.1.5 Ensure permissions on /etc/gshadow are configured
echo
echo -e "${RED}6.1.5${NC} Ensure permissions on /etc/gshadow are configured"
chown root:shadow /etc/shadow && chmod o-rwx,g-wx /etc/shadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow are configured"
  fail=$((fail + 1))
fi

# 6.1.6 Ensure permissions on /etc/passwd- are configured
echo
echo -e "${RED}6.1.6${NC} Ensure permissions on /etc/passwd- are configured"
chown root:root /etc/passwd- && chmod u-x,go-wx /etc/passwd-
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd- are configured"
  fail=$((fail + 1))
fi

# 6.1.7 Ensure permissions on /etc/shadow- are configured
echo
echo -e "${RED}6.1.7${NC} Ensure permissions on /etc/shadow- are configured"
chown root:shadow /etc/shadow- && chmod o-rwx,g-rw /etc/shadow-
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow- are configured"
  fail=$((fail + 1))
fi

# 6.1.8 Ensure permissions on /etc/group- are configured
echo
echo -e "${RED}6.1.8${NC} Ensure permissions on /etc/group- are configured"
chown root:root /etc/group- && chmod u-x,go-wx /etc/group-
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group- are configured"
  fail=$((fail + 1))
fi

# 6.1.9 Ensure permissions on /etc/gshadow- are configured
echo
echo -e "${RED}6.1.9${NC} Ensure permissions on /etc/gshadow- are configured"
chown root:shadow /etc/gshadow- && chmod o-rwx,g-rw /etc/gshadow-
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow- are configured"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 6.2 System Maintenance - User and Group Settings
echo
echo -e "${BLUE}6.2 System Maintenance - User and Group Settings${NC}"

# 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd
echo
echo -e "${RED}6.2.2${NC} Ensure no legacy "+" entries exist in /etc/passwd"
sed -ri '/^\+:.*$/ d' /etc/passwd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy "+" entries exist in /etc/passwd"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy "+" entries exist in /etc/passwd"
  fail=$((fail + 1))
fi

# 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow
echo
echo -e "${RED}6.2.3${NC} Ensure no legacy "+" entries exist in /etc/shadow"
sed -ri '/^\+:.*$/ d' /etc/shadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy "+" entries exist in /etc/shadow"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy "+" entries exist in /etc/shadow"
  fail=$((fail + 1))
fi

# 6.2.4 Ensure no legacy "+" entries exist in /etc/group
echo
echo -e "${RED}6.2.4${NC} Ensure no legacy "+" entries exist in /etc/group"
sed -ri '/^\+:.*$/ d' /etc/group
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy '+' entries exist in /etc/group"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy '+' entries exist in /etc/group"
  fail=$((fail + 1))
fi

############################################################################################################################
############################################################################################################################

echo
echo -e "${GREEN}Remediation script for Ubuntu 18.04 executed successfully!!${NC}"
echo
echo -e "${YELLOW}Summary:${NC}"
echo -e "${YELLOW}Remediation Passed:${NC} $success" 
echo -e "${YELLOW}Remediation Failed:${NC} $fail"

###########################################################################################################################
############################################################################################################################
