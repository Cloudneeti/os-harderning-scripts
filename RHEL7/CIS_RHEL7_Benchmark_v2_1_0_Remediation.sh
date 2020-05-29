#!/bin/bash
 
: '
#SYNOPSIS
    Quick win script for remediation of RHEL 7 baseline misconfigurations.
.DESCRIPTION
    This script will remediation all possible OS baseline misconfigurations for RHEL 7 based Virtual machines.
 
.NOTES
 
    Copyright (c) Cloudneeti. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
    Version: 1.0
    # PREREQUISITE
 
.EXAMPLE
    Command to execute : bash CIS_RHEL7_Benchmark_v2_1_0_Remediation.sh
.INPUTS
 
.OUTPUTS
    None
'

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'

yum update -y && yum install wget -y

##Category 1.1 Initial Setup - Filesystem Configuration
echo
echo -e "${BLUE}1. Initial Setup - Filesystem Configuration${NC}"

#Ensure mounting of cramfs filesystems is disabled
echo
echo -e "${RED}1.1.1.1${NC} Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs | grep "^install /bin/true$" || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
rhel_1_1_1_1=$?
lsmod | egrep "^cramfs\s" && rmmod cramfs
if [[ "$rhel_1_1_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of cramfs filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of cramfs filesystems is disabled"
fi

#Ensure mounting of freevxfs filesystems is disabled
echo
echo -e "${RED}1.1.1.2${NC} Ensure mounting of freevxfs filesystems is disabled"
modprobe -n -v freevxfs | grep "^install /bin/true$" || echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
rhel_1_1_1_2=$?
lsmod | egrep "^freevxfs\s" && rmmod freevxfs
if [[ "$rhel_1_1_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of freevxfs filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of freevxfs filesystems is disabled"
fi

# Ensure mounting of jffs2 filesystems is disabled
echo
echo -e "${RED}1.1.1.3${NC} Ensure mounting of jffs2 filesystems is disabled"
rhel_1_1_1_3="$(modprobe -n -v jffs2 | grep "^install /bin/true$" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_3=$?
lsmod | egrep "^jffs2\s" && rmmod jffs2
if [[ "$rhel_1_1_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of jffs2 filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of jffs2 filesystems is disabled"
fi

# Ensure mounting of hfs filesystems is disabled
echo 
echo -e "${RED}1.1.1.4${NC} Ensure mounting of hfs filesystems is disabled"
rhel_1_1_1_4="$(modprobe -n -v hfs | grep "^install /bin/true$" || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_4=$?
lsmod | egrep "^hfs\s" && rmmod hfs
if [[ "$rhel_1_1_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfs filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfs filesystems is disabled"
fi

# Ensure mounting of hfsplus filesystems is disabled
echo
echo -e "${RED}1.1.1.5${NC} Ensure mounting of hfsplus filesystems is disabled"
rhel_1_1_1_5="$(modprobe -n -v hfsplus | grep "^install /bin/true$" || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_5=$?
lsmod | egrep "^hfsplus\s" && rmmod hfsplus
if [[ "$rhel_1_1_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfsplus filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfsplus filesystems is disabled"
fi

# Ensure mounting of squashfs filesystems is disabled
echo
echo -e "${RED}1.1.1.6${NC} Ensure mounting of squashfs filesystems is disabled"
rhel_1_1_1_6="$(modprobe -n -v squashfs | grep "^install /bin/true$" || echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_6=$?
lsmod | egrep "^squashfs\s" && rmmod squashfs
if [[ "$rhel_1_1_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of squashfs filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of squashfs filesystems is disabled"
fi

# Ensure mounting of udf filesystems is disabled
echo
echo -e "${RED}1.1.1.7${NC} Ensure mounting of udf filesystems is disabled"
rhel_1_1_1_7="$(modprobe -n -v udf | grep "^install /bin/true$" || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_7=$?
lsmod | egrep "^udf\s" && rmmod udf
if [[ "$rhel_1_1_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of udf filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of udf filesystems is disabled"
fi

# Ensure mounting of FAT filesystems is disabled
echo
echo -e "${RED}1.1.1.8${NC} Ensure mounting of FAT filesystems is disabled"
rhel_1_1_1_8="$(modprobe -n -v vfat | grep "^install /bin/true$" || echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_8=$?
lsmod | egrep "^vfat\s" && rmmod vfat
if [[ "$rhel_1_1_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of FAT filesystems is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of FAT filesystems is disabled"
fi

# Ensure sticky bit is set on all world-writable directories
echo
echo -e "${RED}1.1.21${NC} Ensure sticky bit is set on all world-writable directories"
rhel_1_1_21="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t)"
rhel_1_1_21=$?
if [[ "$rhel_1_1_21" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure sticky bit is set on all world-writable directories"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure sticky bit is set on all world-writable directories"
fi

# Disable Automounting
echo
echo -e "${RED}1.1.22${NC} Disable Automounting"
rhel_1_1_22="$(systemctl disable autofs.service)"
rhel_1_1_22=$?
if [[ "$rhel_1_1_22" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Disable Automounting"
else
  echo -e "${RED}UnableToRemediate:${NC} Disable Automounting"
fi

# Ensure gpgcheck is globally activated
echo
echo -e "${RED}1.2.2${NC} Ensure gpgcheck is globally activated"
rhel_1_2_2="$(egrep -q "^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$" /etc/yum.conf && sed -ri "s/^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/\1gpgcheck=1\2/" /etc/yum.conf || echo "gpgcheck=1" >> /etc/yum.conf)"
rhel_1_2_2=$?
rhel_1_2_2_temp=0
for file in /etc/yum.repos.d/*; do
  rhel_1_2_2_temp_2="$(egrep -q "^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$" $file && sed -ri "s/^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/\1gpgcheck=1\2/" $file || echo "gpgcheck=1" >> $file)"
  rhel_1_2_2_temp_2=$?
  if [[ "$rhel_1_2_2_temp_2" -eq 0 ]]; then
    ((rhel_1_2_2_temp=rhel_1_2_2_temp+1))
  fi
done
rhel_1_2_2_temp_2="$( ls -1q /etc/yum.repos.d/* | wc -l)"
if [[ "$rhel_1_2_2" -eq 0 ]] && [[ "$rhel_1_2_2_temp" -eq "rhel_1_2_2_temp_2" ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure gpgcheck is globally activated"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure gpgcheck is globally activated"
fi

# Ensure AIDE is installed
echo
echo -e "${RED}1.3.1${NC} Ensure AIDE is installed"
rhel_1_3_1="$(rpm -q aide || yum -y install aide)"
rhel_1_3_1=$?
if [[ "$rhel_1_3_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure AIDE is installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure AIDE is installed"
fi

# Ensure filesystem integrity is regularly checked
echo
echo -e "${RED}1.3.2${NC} Ensure filesystem integrity is regularly checked"
rhel_1_3_2="$(crontab -u root -l; crontab -u root -l | egrep -q "^0 5 \* \* \* /usr/sbin/aide --check$" || echo "0 5 * * * /usr/sbin/aide --check" ) | crontab -u root -)"
rhel_1_3_2=$?
if [[ "$rhel_1_3_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure filesystem integrity is regularly checked"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure filesystem integrity is regularly checked"
fi

# Ensure permissions on bootloader config are configured
echo
echo -e "${RED}1.3.2${NC} Ensure permissions on bootloader config are configured\n"
rhel_1_4_1="$(chmod g-r-w-x,o-r-w-x /boot/grub2/grub.cfg)"
rhel_1_4_1=$?
if [[ "$rhel_1_4_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on bootloader config are configured"
fi

# Ensure authentication required for single user mode
echo
echo -e "${RED}1.4.3${NC} Ensure authentication required for single user mode"
rhel_1_4_3_rule1="$(egrep -q "^\s*ExecStart" /usr/lib/systemd/system/rescue.service && sed -ri "s/(^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*).*$/\1-\/bin\/sh -c \"\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default\"/" /usr/lib/systemd/system/rescue.service || echo "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /usr/lib/systemd/system/rescue.service)"
rhel_1_4_3_rule1=$?
rhel_1_4_3_rule2="$(egrep -q "^\s*ExecStart" /usr/lib/systemd/system/emergency.service && sed -ri "s/(^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*).*$/\1-\/bin\/sh -c \"\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default\"/" /usr/lib/systemd/system/emergency.service || echo "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /usr/lib/systemd/system/emergency.service)"
rhel_1_4_3_rule1=$?
if [[ "$rhel_1_4_3_rule1" -eq 0 ]] && [[ "$rhel_1_4_3_rule2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure authentication required for single user mode"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure authentication required for single user mode"
fi

# Ensure core dumps are restricted
echo
echo -e "${RED}1.5.1${NC} Ensure core dumps are restricted"
rhel_1_5_1_temp_1="$(egrep -q "^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$" /etc/security/limits.conf && sed -ri "s/^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$/\1* hard core 0\2/" /etc/security/limits.conf || echo "* hard core 0" >> /etc/security/limits.conf)"
rhel_1_5_1_temp_1=$?
rhel_1_5_1_temp_2="$(echo "* hard core 0" >> /etc/security/limits.d/*)"
rhel_1_5_1_temp_2=$?
rhel_1_5_1_temp_3="$(egrep -q "^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$/\1fs.suid_dumpable = 0\2/" /etc/sysctl.conf || echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf)"
rhel_1_5_1_temp_3=$?
rhel_1_5_1_temp_4="$(egrep -q "^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.d/*  || echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/*)"
rhel_1_5_1_temp_4=$?
rhel_1_5_1_temp_5="$(sysctl -w fs.suid_dumpable=0)"
rhel_1_5_1_temp_5=$?
if [[ "$rhel_1_5_1_temp_1" -eq 0 ]] && [[ "$rhel_1_5_1_temp_2" -eq 0 ]] && [[ "$rhel_1_5_1_temp_3" -eq 0 ]] && [[ "$rhel_1_5_1_temp_4" -eq 0 ]] && [[ "$rhel_1_5_1_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure core dumps are restricted"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure core dumps are restricted"
fi

# Ensure address space layout randomization (ASLR) is enabled
echo
echo -e "${RED}1.5.3${NC} Ensure address space layout randomization (ASLR) is enabled"
rhel_1_5_3_temp_1="$(egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf)"
rhel_1_5_3_temp_1=$?
rhel_1_5_3_temp_2="$(echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/*)"
rhel_1_5_3_temp_2=$?
rhel_1_5_3_temp_3="$(sysctl -w kernel.randomize_va_space=2)"
rhel_1_5_3_temp_3=$?
if [[ "$rhel_1_5_3_temp_1" -eq 0 ]] && [[ "$rhel_1_5_3_temp_2" -eq 0 ]] && [[ "$rhel_1_5_3_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure address space layout randomization (ASLR) is enabled"
fi

# Ensure prelink is disabled
echo
echo -e "${RED}1.5.4${NC} Ensure prelink is disabled"
rhel_1_5_4="$(rpm -q prelink && yum -y remove prelink)"
rhel_1_5_4=$?
if [[ "$rhel_1_5_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure prelink is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure prelink is disabled"
fi

# Ensure message of the day is configured properly
echo
echo -e "${RED}1.7.1.1${NC} Ensure message of the day is configured properly"
rhel_1_7_1_1="$(sed -ri 's/(\\v|\\r|\\m|\\s)//g' /etc/motd)"
rhel_1_7_1_1=$?
if [[ "$rhel_1_7_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure message of the day is configured properly"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure message of the day is configured properly"
fi

# Ensure local login warning banner is configured properly
echo
echo -e "${RED}1.7.1.2${NC} Ensure local login warning banner is configured properly"
rhel_1_7_1_2="$(echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue)"
rhel_1_7_1_2=$?
if [[ "$rhel_1_7_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure local login warning banner is configured properly"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure local login warning banner is configured properly"
fi

# Ensure remote login warning banner is configured properly
echo
echo -e "${RED}1.7.1.3${NC} Ensure remote login warning banner is configured properly"
rhel_1_7_1_3="$(echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net)"
rhel_1_7_1_3=$?
if [[ "$rhel_1_7_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure remote login warning banner is configured properly"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure remote login warning banner is configured properly"
fi

# Ensure permissions on /etc/motd are configured
echo
echo -e "${RED}1.7.1.4${NC} Ensure permissions on /etc/motd are configured"
rhel_1_7_1_4="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/motd)"
rhel_1_7_1_4=$?
if [[ "$rhel_1_7_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/motd are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/motd are configured"
fi

# Ensure permissions on /etc/issue are configured
echo
echo -e "${RED}1.7.1.5${NC} Ensure permissions on /etc/issue are configured"
rhel_1_7_1_5="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/issue)"
rhel_1_7_1_5=$?
if [[ "$rhel_1_7_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/issue are configured"
fi

# Ensure permissions on /etc/issue.net are configured
echo
echo -e "${RED}1.7.1.6${NC} Ensure permissions on /etc/issue.net are configured"
rhel_1_7_1_6="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/issue.net)"
rhel_1_7_1_6=$?
if [[ "$rhel_1_7_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue.net are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/issue.net are configured"
fi

# Ensure SELinux is installed
echo
echo -e "${RED}1.6.2${NC} Ensure SELinux is installed"
rhel_1_6_2="$(rpm -q libselinux || yum -y install libselinux)"
rhel_1_6_2=$?
if [[ "$rhel_1_6_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SELinux is installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SELinux is installed"
fi

# Ensure SETroubleshoot is not installed
echo
echo -e "${RED}1.6.1.4${NC} Ensure SETroubleshoot is not installed"
rhel_1_6_1_4="$(rpm -q setroubleshoot && yum -y remove setroubleshoot)"
rhel_1_6_1_4=$?
if [[ "$rhel_1_6_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SETroubleshoot is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SETroubleshoot is not installed"
fi

# Ensure the MCS Translation Service (mcstrans) is not installed
echo
echo -e "${RED}1.6.1.5${NC} Ensure the MCS Translation Service (mcstrans) is not installed"
rhel_1_6_1_5="$(rpm -q mcstrans && yum -y remove mcstrans)"
rhel_1_6_1_5=$?
if [[ "$rhel_1_6_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure the MCS Translation Service (mcstrans) is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the MCS Translation Service (mcstrans) is not installed"
fi

echo -e "${BLUE}2. RHEL 7 - Services ${NC}"

# Ensure chargen services are not enabled
echo
echo -e "${RED}2.1.1${NC} Ensure chargen services are not enabled"
rhel_2_1_1="$(chkconfig chargen off)"
rhel_2_1_1=$?
if [[ "$rhel_2_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure chargen services are not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure chargen services are not enabled"
fi 

# Ensure daytime services are not enabled
echo
echo -e "${RED}2.1.2${NC} Ensure daytime services are not enabled"
rhel_2_1_2="$(chkconfig daytime off)"
rhel_2_1_2=$?
if [[ "$rhel_2_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure daytime services are not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure daytime services are not enabled"
fi

# Ensure discard services are not enabled
echo
echo -e "${RED}2.1.3${NC} Ensure discard services are not enabled"
rhel_2_1_3="$(chkconfig discard off)"
rhel_2_1_3=$?
if [[ "$rhel_2_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure discard services are not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure discard services are not enabled"
fi

# Ensure echo services are not enabled
echo
echo -e "${RED}2.1.4${NC} Ensure echo services are not enabled"
rhel_2_1_4="$(chkconfig echo off)"
rhel_2_1_4=$?
if [[ "$rhel_2_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure echo services are not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure echo services are not enabled"
fi

# Ensure time services are not enabled
echo
echo -e "${RED}2.1.5${NC} Ensure time services are not enabled"
rhel_2_1_5="$(chkconfig time off)"
rhel_2_1_5=$?
if [[ "$rhel_2_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure time services are not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure time services are not enabled"
fi

# Ensure tftp server is not enabled
echo
echo -e "${RED}2.1.6${NC} Ensure tftp server is not enabled"
rhel_2_1_6="$(chkconfig tftp off)"
rhel_2_1_6=$?
systemctl disable tftp.socket.service
if [[ "$rhel_2_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure tftp server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure tftp server is not enabled"
fi

# Ensure xinetd is not enabled
echo
echo -e "${RED}2.1.7${NC} Ensure xinetd is not enabled"
rhel_2_1_7="$(systemctl disable xinetd.service)"
rhel_2_1_7=$?
if [[ "$rhel_2_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure xinetd is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure xinetd is not enabled"
fi

# Ensure time synchronization is in use
echo
echo -e "${RED}2.2.1.1${NC} Ensure time synchronization is in use"
rhel_2_2_1_1="$(rpm -q ntp || rpm -q chrony || yum -y install chrony)"
rhel_2_2_1_1=$?
if [[ "$rhel_2_2_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure time synchronization is in use"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure time synchronization is in use"
fi

# Ensure ntp is configured
echo
echo -e "${RED}2.2.1.2${NC} Ensure ntp is configured"
if rpm -q ntp >/dev/null; then
  rhel_2_2_1_1_temp_1="$(egrep -q "^\s*restrict(\s+-4)?\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict(\s+-4)?\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict\2 default kod nomodify notrap nopeer noquery\4/" /etc/ntp.conf || echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf)"
  rhel_2_2_1_1_temp_1=$?
  rhel_2_2_1_1_temp_2="$(egrep -q "^\s*restrict\s+-6\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict\s+-6\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict -6 default kod nomodify notrap nopeer noquery\3/" /etc/ntp.conf || echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf)"
  rhel_2_2_1_1_temp_2=$?
  rhel_2_2_1_1_temp_3="$(egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/sysconfig/ntpd && sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u ntp:ntp\"\3/ }' /etc/sysconfig/ntpd && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u ntp:ntp\3\"\4/" /etc/sysconfig/ntpd || echo OPTIONS=\"-u ntp:ntp\" >> /etc/sysconfig/ntpd)"
  rhel_2_2_1_1_temp_3=$?
  if [[ "$rhel_2_2_1_1_temp_1" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_2" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_3" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure ntp is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure ntp is configured"
  fi
else
  yum install ntp -y && systemctl enable ntpd
  rhel_2_2_1_1_temp_1="$(echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf)"
  rhel_2_2_1_1_temp_1=$?
  rhel_2_2_1_1_temp_2="$(echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf)"
  rhel_2_2_1_1_temp_2=$?
  rhel_2_2_1_1_temp_3="$(echo OPTIONS=\"-u ntp:ntp\" >> /etc/sysconfig/ntpd)"
  rhel_2_2_1_1_temp_3=$?
  if [[ "$rhel_2_2_1_1_temp_1" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_2" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_3" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure ntp is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure ntp is configured"
  fi
fi

# Ensure chrony is configured
echo
echo -e "${RED}2.2.1.3${NC} Ensure chrony is configured"
if rpm -q chrony >/dev/null; then
  rhel_2_2_1_3="$(egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/sysconfig/chronyd && sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u chrony\"\3/ }' /etc/sysconfig/chronyd && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u chrony\3\"\4/" /etc/sysconfig/chronyd || echo OPTIONS=\"-u chrony\" >> /etc/sysconfig/chronyd)"
  rhel_2_2_1_3=$?
  if [[ "$rhel_2_2_1_3" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure chrony is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure chrony is configured"
  fi
else
  yum install chrony -y && systemctl start chronyd && systemctl enable chronyd
  rhel_2_2_1_3="$(echo OPTIONS=\"-u chrony\" >> /etc/sysconfig/chronyd)"
  rhel_2_2_1_3=$?
  if [[ "$rhel_2_2_1_3" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure chrony is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure chrony is configured"
  fi
fi

# Ensure X Window System is not installed
echo
echo -e "${RED}2.2.2${NC} Ensure X Window System is not installed"
rhel_2_2_2="$(yum -y remove xorg-x11*)"
rhel_2_2_2=$?
if [[ "$rhel_2_2_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure X Window System is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure X Window System is not installed"
fi

# Ensure Avahi Server is not enabled
echo
echo -e "${RED}2.2.3${NC} Ensure Avahi Server is not enabled"
rhel_2_2_3="$(systemctl disable avahi-daemon.service || yum erase avahi -y)"
rhel_2_2_3=$?
if [[ "$rhel_2_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Avahi Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Avahi Server is not enabled"
fi

# Ensure CUPS is not enabled
echo
echo -e "${RED}2.2.4${NC} Ensure CUPS is not enabled"
rhel_2_2_4="$(systemctl disable cups.service  || yum erase cups -y)"
rhel_2_2_4=$?
if [[ "$rhel_2_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure CUPS is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure CUPS is not enabled"
fi

# Ensure DHCP Server is not enabled
echo
echo -e "${RED}2.2.5${NC} Ensure DHCP Server is not enabled"
rhel_2_2_5="$(systemctl disable dhcpd.service || yum erase dhcpd -y)"
rhel_2_2_5=$?
if [[ "$rhel_2_2_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DHCP Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DHCP Server is not enabled"
fi

# Ensure LDAP server is not enabled
echo
echo -e "${RED}2.2.6${NC} Ensure LDAP server is not enabled"
rhel_2_2_6="$(systemctl disable slapd.service || yum erase slapd -y)"
rhel_2_2_6=$?
if [[ "$rhel_2_2_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure LDAP server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure LDAP server is not enabled"
fi

# Ensure NFS and RPC are not enabled
echo
echo -e "${RED}2.2.7${NC} Ensure NFS and RPC are not enabled"
rhel_2_2_7_temp_1="$(systemctl disable nfs.service || yum erase nfs -y)"
rhel_2_2_7_temp_1=$?
rhel_2_2_7_temp_2="$(systemctl disable rpcbind.service || yum erase rpcbind -y)"
rhel_2_2_7_temp_2=$?
if [[ "$rhel_2_2_7_temp_1" -eq 0 ]] && [[ "$rhel_2_2_7_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NFS and RPC are not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NFS and RPC are not enabled"
fi

# Ensure DNS Server is not enabled
echo
echo -e "${RED}2.2.8${NC} Ensure DNS Server is not enabled"
rhel_2_2_8="$(systemctl disable named.service || yum erase named -y)"
rhel_2_2_8=$?
if [[ "$rhel_2_2_8" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DNS Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DNS Server is not enabled"
fi

# Ensure FTP Server is not enabled
echo
echo -e "${RED}2.2.9${NC} Ensure FTP Server is not enabled"
rhel_2_2_9="$(systemctl disable vsftpd.service || yum erase vsftpd -y)"
rhel_2_2_9=$?
if [[ "$rhel_2_2_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure FTP Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure FTP Server is not enabled"
fi

# Ensure HTTP server is not enabled
echo
echo -e "${RED}2.2.10${NC} Ensure HTTP server is not enabled"
rhel_2_2_10="$(systemctl disable httpd.service || yum erase httpd -y)"
rhel_2_2_10=$?
if [[ "$rhel_2_2_10" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure HTTP server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure HTTP server is not enabled"
fi

# Ensure IMAP and POP3 server is not enabled
echo
echo -e "${RED}2.2.11${NC} Ensure IMAP and POP3 server is not enabled"
rhel_2_2_11="$(systemctl disable dovecot.service || yum erase dovecot -y)"
rhel_2_2_11=$?
if [[ "$rhel_2_2_11" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IMAP and POP3 server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IMAP and POP3 server is not enabled"
fi

# Ensure Samba is not enabled
echo
echo -e "${RED}2.2.12${NC} Ensure Samba is not enabled"
rhel_2_2_12="$(systemctl disable smb.service || yum erase smb -y)"
rhel_2_2_12=$?
if [[ "$rhel_2_2_12" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Samba is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Samba is not enabled"
fi

# Ensure HTTP Proxy Server is not enabled
echo
echo -e "${RED}2.2.13${NC} Ensure HTTP Proxy Server is not enabled"
rhel_2_2_13="$(systemctl disable squid.service || yum erase squid -y)"
rhel_2_2_13=$?
if [[ "$rhel_2_2_13" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure HTTP Proxy Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure HTTP Proxy Server is not enabled"
fi

# Ensure SNMP Server is not enabled
echo
echo -e "${RED}2.2.14${NC} Ensure SNMP Server is not enabled"
rhel_2_2_14="$(systemctl disable snmpd.service || yum erase snmpd -y)"
rhel_2_2_14=$?
if [[ "$rhel_2_2_14" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SNMP Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SNMP Server is not enabled"
fi

# Ensure NIS Server is not enabled
echo
echo -e "${RED}2.2.16${NC} Ensure NIS Server is not enabled"
rhel_2_2_16="$(systemctl disable ypserv.service || yum erase ypserv -y)"
rhel_2_2_16=$?
if [[ "$rhel_2_2_16" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NIS Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NIS Server is not enabled"
fi

# Ensure rsh server is not enabled
echo
echo -e "${RED}2.2.17${NC} Ensure rsh server is not enabled"
rhel_2_2_17="$(systemctl disable rsh.socket.service || yum erase rsh -y)"
rhel_2_2_17=$?
systemctl disable rlogin.socket.service
systemctl disable rexec.socket.service
if [[ "$rhel_2_2_17" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsh server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh server is not enabled"
fi

# Ensure talk server is not enabled
echo
echo -e "${RED}2.2.18${NC} Ensure talk server is not enabled"
rhel_2_2_18="$(systemctl disable ntalk.service || yum erase ntalk -y)"
rhel_2_2_18=$?
if [[ "$rhel_2_2_18" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure talk server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure talk server is not enabled"
fi

# Ensure telnet server is not enabled
echo
echo -e "${RED}2.2.19${NC} Ensure telnet server is not enabled"
rhel_2_2_19="$(systemctl disable telnet.socket.service || yum erase telnet -y)"
rhel_2_2_19=$?
if [[ "$rhel_2_2_19" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure telnet server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure telnet server is not enabled"
fi

# Ensure rsync service is not enabled
echo
echo -e "${RED}2.2.21${NC} Ensure rsync service is not enabled"
rhel_2_2_21="$(systemctl disable rsyncd.service || yum erase rsyncd -y)"
rhel_2_2_21=$?
if [[ "$rhel_2_2_21" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsync service is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsync service is not enabled"
fi

# Ensure NIS Client is not installed
echo
echo -e "${RED}2.3.1${NC} Ensure NIS Client is not installed"
rhel_2_3_1="$(rpm -q ypbind && yum -y erase ypbind)"
rhel_2_3_1=$?
if [[ "$rhel_2_3_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NIS Client is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NIS Client is not installed"
fi

# Ensure rsh client is not installed
echo
echo -e "${RED}2.3.2${NC} Ensure rsh client is not installed"
rhel_2_3_2="$(rpm -q rsh && yum -y erase rsh)"
rhel_2_3_2=$?
if [[ "$rhel_2_3_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsh client is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh client is not installed"
fi

# Ensure talk client is not installed
echo
echo -e "${RED}2.3.3${NC} Ensure talk client is not installed"
rhel_2_3_3="$(rpm -q talk && yum -y erase talk)"
rhel_2_3_3=$?
if [[ "$rhel_2_3_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure talk client is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure talk client is not installed"
fi

# Ensure telnet client is not installed
echo
echo -e "${RED}2.3.4${NC} Ensure telnet client is not installed"
rhel_2_3_4="$(rpm -q telnet && yum -y erase telnet)"
rhel_2_3_4=$?
if [[ "$rhel_2_3_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure telnet client is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure telnet client is not installed"
fi

# Ensure LDAP client is not installed
echo
echo -e "${RED}2.3.5${NC} Ensure LDAP client is not installed"
rhel_2_3_5="$(rpm -q openldap-clients && yum -y erase openldap-clients)"
rhel_2_3_5=$?
if [[ "$rhel_2_3_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure LDAP client is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure LDAP client is not installed"
fi

echo -e "${BLUE}3. RHEL 7 - Network Configuration ${NC}"

# Ensure IP forwarding is disabled
echo
echo -e "${RED}3.1.1${NC} Ensure IP forwarding is disabled"
rhel_3_1_1_temp_1="$(egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf)"
rhel_3_1_1_temp_1=$?
rhel_3_1_1_temp_2="$(echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/*)"
rhel_3_1_1_temp_2=$?
rhel_3_1_1_temp_3="$(sysctl -w net.ipv4.ip_forward=0)"
rhel_3_1_1_temp_3=$?
rhel_3_1_1_temp_4="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_1_1_temp_4=$?
if [[ "$rhel_3_1_1_temp_1" -eq 0 ]] && [[ "$rhel_3_1_1_temp_2" -eq 0 ]] && [[ "$rhel_3_1_1_temp_3" -eq 0 ]] && [[ "$rhel_3_1_1_temp_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IP forwarding is disabled"
fi

# Ensure packet redirect sending is disabled
echo
echo -e "${RED}3.1.2${NC} Ensure packet redirect sending is disabled"
rhel_3_1_2_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_1_2_temp_1=$?
rhel_3_1_2_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_1_2_temp_2=$?
rhel_3_1_2_temp_3="$(sysctl -w net.ipv4.conf.all.send_redirects=0)"
rhel_3_1_2_temp_3=$?
rhel_3_1_2_temp_4="$(sysctl -w net.ipv4.conf.default.send_redirects=0)"
rhel_3_1_2_temp_4=$?
rhel_3_1_2_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_1_2_temp_5=$?
if [[ "$rhel_3_1_2_temp_1" -eq 0 ]] && [[ "$rhel_3_1_2_temp_2" -eq 0 ]] && [[ "$rhel_3_1_2_temp_3" -eq 0 ]] && [[ "$rhel_3_1_2_temp_4" -eq 0 ]] && [[ "$rhel_3_1_2_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure packet redirect sending is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure packet redirect sending is disabled"
fi

# Ensure source routed packets are not accepted
echo
echo -e "${RED}3.2.1${NC} Ensure source routed packets are not accepted"
rhel_3_2_1_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf)"
rhel_3_2_1_temp_1=$?
rhel_3_2_1_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf)"
rhel_3_2_1_temp_2=$?
rhel_3_2_1_temp_3="$(sysctl -w net.ipv4.conf.all.accept_source_route=0)"
rhel_3_2_1_temp_3=$?
rhel_3_2_1_temp_4="$(sysctl -w net.ipv4.conf.default.accept_source_route=0)"
rhel_3_2_1_temp_4=$?
rhel_3_2_1_temp_5="$sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_1_temp_5=$?
if [[ "$rhel_3_2_1_temp_1" -eq 0 ]] && [[ "$rhel_3_2_1_temp_2" -eq 0 ]] && [[ "$rhel_3_2_1_temp_3" -eq 0 ]] && [[ "$rhel_3_2_1_temp_4" -eq 0 ]] && [[ "$rhel_3_2_1_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure source routed packets are not accepted"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure source routed packets are not accepted"
fi

# Ensure ICMP redirects are not accepted
echo
echo -e "${RED}3.2.2${NC} Ensure ICMP redirects are not accepted"
rhel_3_2_2_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_2_2_temp_1=$?
rhel_3_2_2_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_2_2_temp_2=$?
rhel_3_2_2_temp_3="$(sysctl -w net.ipv4.conf.all.accept_redirects=0)"
rhel_3_2_2_temp_3=$?
rhel_3_2_2_temp_4="$(sysctl -w net.ipv4.conf.default.accept_redirects=0)"
rhel_3_2_2_temp_4=$?
rhel_3_2_2_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_2_temp_5=$?
if [[ "$rhel_3_2_2_temp_1" -eq 0 ]] && [[ "$rhel_3_2_2_temp_2" -eq 0 ]] && [[ "$rhel_3_2_2_temp_3" -eq 0 ]] && [[ "$rhel_3_2_2_temp_4" -eq 0 ]] && [[ "$rhel_3_2_2_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure ICMP redirects are not accepted"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure ICMP redirects are not accepted"
fi

# Ensure secure ICMP redirects are not accepted
echo
echo -e "${RED}3.2.3${NC} Ensure secure ICMP redirects are not accepted"
rhel_3_2_3_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.secure_redirects = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_2_3_temp_1=$?
rhel_3_2_3_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.secure_redirects = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_2_3_temp_2=$?
rhel_3_2_3_temp_3="$(sysctl -w net.ipv4.conf.all.secure_redirects=0)"
rhel_3_2_3_temp_3=$?
rhel_3_2_3_temp_4="$(sysctl -w net.ipv4.conf.default.secure_redirects=0)"
rhel_3_2_3_temp_4=$?
rhel_3_2_3_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_3_temp_5=$?
if [[ "$rhel_3_2_3_temp_1" -eq 0 ]] && [[ "$rhel_3_2_3_temp_2" -eq 0 ]] && [[ "$rhel_3_2_3_temp_3" -eq 0 ]] && [[ "$rhel_3_2_3_temp_4" -eq 0 ]] && [[ "$rhel_3_2_3_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure secure ICMP redirects are not accepted"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure secure ICMP redirects are not accepted"
fi

# Ensure suspicious packets are logged
echo
echo -e "${RED}3.2.4${NC} Ensure suspicious packets are logged"
rhel_3_2_4_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.log_martians\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.log_martians\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.log_martians = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf)"
rhel_3_2_4_temp_1=$?
rhel_3_2_4_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.log_martians\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.log_martians\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.log_martians = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf)"
rhel_3_2_4_temp_2=$?
rhel_3_2_4_temp_3="$(sysctl -w net.ipv4.conf.all.log_martians=1)"
rhel_3_2_4_temp_3=$?
rhel_3_2_4_temp_4="$(sysctl -w net.ipv4.conf.default.log_martians=1)"
rhel_3_2_4_temp_4=$?
rhel_3_2_4_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_4_temp_5=$?
if [[ "$rhel_3_2_4_temp_1" -eq 0 ]] && [[ "$rhel_3_2_4_temp_2" -eq 0 ]] && [[ "$rhel_3_2_4_temp_3" -eq 0 ]] && [[ "$rhel_3_2_4_temp_4" -eq 0 ]] && [[ "$rhel_3_2_4_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure suspicious packets are logged"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure suspicious packets are logged"
fi

# Ensure broadcast ICMP requests are ignored
echo
echo -e "${RED}3.2.5${NC} Ensure broadcast ICMP requests are ignored"
rhel_3_2_5_temp_1="$(egrep -q "^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_echo_ignore_broadcasts = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf)"
rhel_3_2_5_temp_1=$?
rhel_3_2_5_temp_2="$(sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1)"
rhel_3_2_5_temp_2=$?
rhel_3_2_5_temp_3="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_5_temp_3=$?
if [[ "$rhel_3_2_5_temp_1" -eq 0 ]] && [[ "$rhel_3_2_5_temp_2" -eq 0 ]] && [[ "$rhel_3_2_5_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure broadcast ICMP requests are ignored"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure broadcast ICMP requests are ignored"
fi

# Ensure bogus ICMP responses are ignored
echo
echo -e "${RED}3.2.6${NC} Ensure bogus ICMP responses are ignored"
rhel_3_2_6_temp_1="$(egrep -q "^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_ignore_bogus_error_responses = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf)"
rhel_3_2_6_temp_1=$?
rhel_3_2_6_temp_2="$(sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1)"
rhel_3_2_6_temp_2=$?
rhel_3_2_6_temp_3="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_6_temp_3=$?
if [[ "$rhel_3_2_6_temp_1" -eq 0 ]] && [[ "$rhel_3_2_6_temp_2" -eq 0 ]] && [[ "$rhel_3_2_6_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure bogus ICMP responses are ignored"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure bogus ICMP responses are ignored"
fi

# Ensure Reverse Path Filtering is enabled
echo
echo -e "${RED}3.2.7${NC} Ensure Reverse Path Filtering is enabled"
rhel_3_2_7_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf)"
rhel_3_2_7_temp_1=$?
rhel_3_2_7_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf)"
rhel_3_2_7_temp_2=$?
rhel_3_2_7_temp_3="$(sysctl -w net.ipv4.conf.all.rp_filter=1)"
rhel_3_2_7_temp_3=$?
rhel_3_2_7_temp_4="$(sysctl -w net.ipv4.conf.default.rp_filter=1)"
rhel_3_2_7_temp_4=$?
rhel_3_2_7_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_7_temp_5=$?
if [[ "$rhel_3_2_7_temp_1" -eq 0 ]] && [[ "$rhel_3_2_7_temp_2" -eq 0 ]] && [[ "$rhel_3_2_7_temp_3" -eq 0 ]] && [[ "$rhel_3_2_7_temp_4" -eq 0 ]] && [[ "$rhel_3_2_7_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Reverse Path Filtering is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Reverse Path Filtering is enabled"
fi

# Ensure TCP SYN Cookies is enabled
echo
echo -e "${RED}3.2.8${NC} Ensure TCP SYN Cookies is enabled"
rhel_3_2_8_temp_1="$(egrep -q "^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.tcp_syncookies = 1\2/" /etc/sysctl.conf || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf)"
rhel_3_2_8_temp_1=$?
rhel_3_2_8_temp_2="$sysctl -w net.ipv4.tcp_syncookies=1)"
rhel_3_2_8_temp_2=$?
rhel_3_2_8_temp_3="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_8_temp_3=$?
if [[ "$rhel_3_2_8_temp_1" -eq 0 ]] && [[ "$rhel_3_2_8_temp_2" -eq 0 ]] && [[ "$rhel_3_2_8_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TCP SYN Cookies is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TCP SYN Cookies is enabled"
fi

# Ensure IPv6 router advertisements are not accepted
echo
echo -e "${RED}3.3.1${NC} Ensure IPv6 router advertisements are not accepted"
rhel_3_3_1_temp_1="$(egrep -q "^(\s*)net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf)"
rhel_3_3_1_temp_1=$?
rhel_3_3_1_temp_2="$(egrep -q "^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf)"
rhel_3_3_1_temp_2=$?
rhel_3_3_1_temp_3="$(sysctl -w net.ipv6.conf.all.accept_ra=0)"
rhel_3_3_1_temp_3=$?
rhel_3_3_1_temp_4="$(sysctl -w net.ipv6.conf.default.accept_ra=0)"
rhel_3_3_1_temp_4=$?
rhel_3_3_1_temp_5="$(sysctl -w net.ipv6.route.flush=1)"
rhel_3_3_1_temp_5=$?
if [[ "$rhel_3_3_1_temp_1" -eq 0 ]] && [[ "$rhel_3_3_1_temp_2" -eq 0 ]] && [[ "$rhel_3_3_1_temp_3" -eq 0 ]] && [[ "$rhel_3_3_1_temp_4" -eq 0 ]] && [[ "$rhel_3_3_1_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IPv6 router advertisements are not accepted"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IPv6 router advertisements are not accepted"
fi

# Ensure IPv6 redirects are not accepted
echo
echo -e "${RED}3.3.2${NC} Ensure IPv6 redirects are not accepted"
rhel_3_3_2_temp_1="$(egrep -q "^(\s*)net.ipv6.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_3_2_temp_1=$?
rhel_3_3_2_temp_2="$(egrep -q "^(\s*)net.ipv6.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf)"
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/*
rhel_3_3_2_temp_2=$?
rhel_3_3_2_temp_3="$(sysctl -w net.ipv6.conf.all.accept_redirects=0)"
rhel_3_3_2_temp_3=$?
rhel_3_3_2_temp_4="$(sysctl -w net.ipv6.conf.default.accept_redirects=0)"
rhel_3_3_2_temp_4=$?
rhel_3_3_2_temp_5="$(sysctl -w net.ipv6.route.flush=1)"
rhel_3_3_2_temp_5=$?
if [[ "$rhel_3_3_2_temp_1" -eq 0 ]] && [[ "$rhel_3_3_2_temp_2" -eq 0 ]] && [[ "$rhel_3_3_2_temp_3" -eq 0 ]] && [[ "$rhel_3_3_2_temp_4" -eq 0 ]] && [[ "$rhel_3_3_2_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IPv6 redirects are not accepted"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IPv6 redirects are not accepted"
fi

# Ensure TCP Wrappers is installed
echo
echo -e "${RED}3.4.1${NC} Ensure TCP Wrappers is installed"
rhel_3_4_1_temp_1="$(rpm -q tcp_wrappers || yum -y install tcp_wrappers)"
rhel_3_4_1_temp_1=$?
rhel_3_4_1_temp_2="$(rpm -q tcp_wrappers-libs || yum -y install tcp_wrappers-libs)"
rhel_3_4_1_temp_2=$?
if [[ "$rhel_3_4_1_temp_1" -eq 0 ]] && [[ "$rhel_3_4_1_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TCP Wrappers is installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TCP Wrappers is installed"
fi

# Ensure /etc/hosts.allow is configured
echo
echo -e "${RED}3.4.2${NC} Ensure /etc/hosts.allow is configured"
rhel_3_4_2="$(touch /etc/hosts.allow)"
rhel_3_4_2=$?
if [[ "$rhel_3_4_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure /etc/hosts.allow is configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure /etc/hosts.allow is configured"
fi

# Ensure /etc/hosts.deny is configured
echo
echo -e "${RED}3.4.3${NC} Ensure /etc/hosts.deny is configured"
rhel_3_4_3="$(touch /etc/hosts.deny)"
rhel_3_4_3=$?
if [[ "$rhel_3_4_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure /etc/hosts.deny is configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure /etc/hosts.deny is configured"
fi

# Ensure permissions on /etc/hosts.allow are configured
echo
echo -e "${RED}3.4.4${NC} Ensure permissions on /etc/hosts.allow are configured"
rhel_3_4_4="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/hosts.allow)"
rhel_3_4_4=$?
if [[ "$rhel_3_4_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/hosts.allow are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/hosts.allow are configured"
fi

# Ensure permissions on /etc/hosts.deny are 644
echo
echo -e "${RED}3.4.5${NC} Ensure permissions on /etc/hosts.deny are configured"
rhel_3_4_5="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/hosts.deny)"
rhel_3_4_5=$?
if [[ "$rhel_3_4_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/hosts.deny are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/hosts.deny are configured"
fi

# Ensure DCCP is disabled
echo
echo -e "${RED}3.5.1${NC} Ensure DCCP is disabled"
rhel_3_5_1="$(modprobe -n -v dccp | grep "^install /bin/true$" || echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_1=$?
lsmod | egrep "^dccp\s" && rmmod dccp
if [[ "$rhel_3_5_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DCCP is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DCCP is disabled"
fi

# Ensure SCTP is disabled
echo
echo -e "${RED}3.5.2${NC} Ensure SCTP is disabled"
rhel_3_5_2="$(modprobe -n -v sctp | grep "^install /bin/true$" || echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_2=$?
lsmod | egrep "^sctp\s" && rmmod sctp
if [[ "$rhel_3_5_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SCTP is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SCTP is disabled"
fi

# Ensure RDS is disabled
echo
echo -e "${RED}3.5.3${NC} Ensure RDS is disabled"
rhel_3_5_3="$(modprobe -n -v rds | grep "^install /bin/true$" || echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_3=$?
lsmod | egrep "^rds\s" && rmmod rds
if [[ "$rhel_3_5_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure RDS is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure RDS is disabled"
fi

# Ensure TIPC is disabled
echo
echo -e "${RED}3.5.4${NC} Ensure TIPC is disabled"
rhel_3_5_4="$(modprobe -n -v tipc | grep "^install /bin/true$" || echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_4=$?
lsmod | egrep "^tipc\s" && rmmod tipc
if [[ "$rhel_3_5_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TIPC is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TIPC is disabled"
fi

# Ensure iptables is installed
echo
echo -e "${RED}3.6.1${NC} Ensure iptables is installed"
rhel_3_6_1="$(rpm -q iptables || yum -y install iptables)"
rhel_3_6_1=$?
if [[ "$rhel_3_6_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure iptables is installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure iptables is installed"
fi

echo -e "${BLUE}4. RHEL 7 - Logging and Auditing ${NC}"

# Ensure rsyslog Service is enabled
echo
echo -e "${RED}4.2.1.1${NC} Ensure rsyslog Service is enabled"
rhel_4_2_1_1="$(rpm -q rsyslog && yum install rsyslog -y && systemctl enable rsyslog.service)"
rhel_4_2_1_1=$?
if [[ "$rhel_4_2_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog Service is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog Service is enabled"
fi

# Ensure syslog-ng service is enabled
echo
echo -e "${RED}4.2.2.1${NC} Ensure syslog-ng service is enabled"
rhel_4_2_2_1="$(rpm -q syslog-ng && systemctl enable syslog-ng.service)"
rhel_4_2_2_1=$?
if [[ "$rhel_4_2_2_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure syslog-ng service is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure syslog-ng service is enabled"
fi

# Ensure rsyslog or syslog-ng is installed
echo
echo -e "${RED}4.2.3${NC} Ensure rsyslog or syslog-ng is installed"
rhel_4_2_3="$(rpm -q rsyslog || rpm -q syslog-ng || yum -y install rsyslog)"
rhel_4_2_3=$?
if [[ "$rhel_4_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog or syslog-ng is installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog or syslog-ng is installed"
fi

# Ensure permissions on all logfiles are configured
echo
echo -e "${RED}4.2.4${NC} Ensure permissions on all logfiles are configured"
rhel_4_2_4="$(chmod -R g-w-x,o-r-w-x /var/log/*)"
rhel_4_2_4=$?
if [[ "$rhel_4_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on all logfiles are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on all logfiles are configuredd"
fi

# Ensure system is disabled when audit logs are full
echo
echo -e "${RED}4.1.1.2${NC} Ensure system is disabled when audit logs are full"
rhel_4_1_1_2_temp_1="$(egrep -q "^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1space_left_action = email\2/" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf)"
rhel_4_1_1_2_temp_1=$?
rhel_4_1_1_2_temp_2="$(egrep -q "^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$/\1action_mail_acct = root\2/" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf)"
rhel_4_1_1_2_temp_2=$?
rhel_4_1_1_2_temp_3="$(egrep -q "^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1admin_space_left_action = halt\2/" /etc/audit/auditd.conf || echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf)"
rhel_4_1_1_2_temp_3=$?
if [[ "$rhel_4_1_1_2_temp_1" -eq 0 ]] && [[ "$rhel_4_1_1_2_temp_2" -eq 0 ]] && [[ "$rhel_4_1_1_2_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure system is disabled when audit logs are full"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure system is disabled when audit logs are full"
fi

# Ensure audit logs are not automatically deleted
echo
echo -e "${RED}4.1.1.3${NC} Ensure audit logs are not automatically deleted"
rhel_4_1_1_3="$(egrep -q "^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$/\1max_log_file_action = keep_logs\2/" /etc/audit/auditd.conf || echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf)"
rhel_4_1_1_3=$?
if [[ "$rhel_4_1_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure audit logs are not automatically deleted"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure audit logs are not automatically deleted"
fi

# Ensure auditd service is enabled
echo
echo -e "${RED}4.1.2${NC} Ensure auditd service is enabled"
rhel_4_1_2="$(systemctl enable auditd.service)"
rhel_4_1_2=$?
if [[ "$rhel_4_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure auditd service is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure auditd service is enabled"
fi

# Ensure auditing for processes that start prior to auditd is enabled
echo
echo -e "${RED}4.1.3${NC} Ensure auditing for processes that start prior to auditd is enabled"
rhel_4_1_3_temp_1="$(egrep -q "^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]+)?\"(\s*#.*)?\s*$" /etc/default/grub && sed -ri '/^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]*)?\"(\s*#.*)?\s*$/ {/^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]+\s+)?audit=\S+(\s+[^\"]+)?\"(\s*#.*)?\s*$/! s/^(\s*GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]+)?)(\"(\s*#.*)?\s*)$/\1 audit=1\3/ }' /etc/default/grub && sed -ri "s/^((\s*)GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]+\s+)?)audit=\S+((\s+[^\"]+)?\"(\s*#.*)?\s*)$/\1audit=1\4/" /etc/default/grub || echo "GRUB_CMDLINE_LINUX=\"audit=1\"" >> /etc/default/grub)"
rhel_4_1_3_temp_1=$?
rhel_4_1_3_temp_2="$(grub2-mkconfig -o /boot/grub2/grub.cfg)"
rhel_4_1_3_temp_2=$?
if [[ "$rhel_4_1_3_temp_1" -eq 0 ]] && [[ "$rhel_4_1_3_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure auditing for processes that start prior to auditd is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure auditing for processes that start prior to auditd is enabled"
fi

# Ensure events that modify date and time information are collected
echo
echo -e "${RED}4.1.4${NC} Ensure events that modify date and time information are collected"
rhel_4_1_4_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-S\s+stime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_4_temp_1=$?
rhel_4_1_4_temp_2="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+clock_settime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_4_temp_2=$?
egrep "^-w\s+/etc/localtime\s+-p\s+wa\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/audit.rules
rhel_4_1_4_temp_3="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+clock_settime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_4_temp_3=$?
if [[ "$rhel_4_1_4_temp_1" -eq 0 ]] && [[ "$rhel_4_1_4_temp_2" -eq 0 ]] && [[ "$rhel_4_1_4_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify date and time information are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify date and time information are collected"
fi

# Ensure events that modify user/group information are collected
echo
echo -e "${RED}4.1.5${NC} Ensure events that modify user/group information are collected"
rhel_4_1_5_temp_1="$(egrep "^-w\s+/etc/group\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_1=$?
rhel_4_1_5_temp_2="$(egrep "^-w\s+/etc/passwd\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_2=$?
rhel_4_1_5_temp_3="$(egrep "^-w\s+/etc/gshadow\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_3=$?
rhel_4_1_5_temp_4="$(egrep "^-w\s+/etc/shadow\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_4=$?
rhel_4_1_5_temp_5="$(egrep "^-w\s+/etc/security/opasswd\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_5=$?
if [[ "$rhel_4_1_5_temp_1" -eq 0 ]] && [[ "$rhel_4_1_5_temp_2" -eq 0 ]] && [[ "$rhel_4_1_5_temp_3" -eq 0 ]] && [[ "$rhel_4_1_5_temp_4" -eq 0 ]] && [[ "$rhel_4_1_5_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify user/group information are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify user/group information are collected"
fi

# Ensure events that modify the system's network environment are collected
echo
echo -e "${RED}4.1.6${NC} Ensure events that modify the system's network environment are collected"
rhel_4_1_6_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_1=$?
rhel_4_1_6_temp_2="$(egrep "^-w\s+/etc/issue\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_2=$?
rhel_4_1_6_temp_3="$(egrep "^-w\s+/etc/issue.net\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_3=$?
rhel_4_1_6_temp_4="$(egrep "^-w\s+/etc/hosts\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_4=$?
egrep "^-w\s+/etc/sysconfig/network\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
rhel_4_1_6_temp_5="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_5=$?
if [[ "$rhel_4_1_6_temp_1" -eq 0 ]] && [[ "$rhel_4_1_6_temp_2" -eq 0 ]] && [[ "$rhel_4_1_6_temp_3" -eq 0 ]] && [[ "$rhel_4_1_6_temp_4" -eq 0 ]] && [[ "$rhel_4_1_6_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's network environment are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify the system's network environment are collected"
fi

# Ensure events that modify the system's Mandatory Access Controls are collected
echo
echo -e "${RED}4.1.7${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
rhel_4_1_7="$(egrep "^-w\s+/etc/selinux/\s+-p\s+wa\s+-k\s+MAC-policy\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_7=$?
if [[ "$rhel_4_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
fi

# Ensure login and logout events are collected
echo
echo -e "${RED}4.1.8${NC} Ensure login and logout events are collected"
rhel_4_1_8_temp_1="$(egrep "^-w\s+/var/run/faillock/\s+-p\s+wa\s+-k\s+logins\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_8_temp_1=$?
rhel_4_1_8_temp_2="$(egrep "^-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_8_temp_2=$?
if [[ "$rhel_4_1_8_temp_1" -eq 0 ]] && [[ "$rhel_4_1_8_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure login and logout events are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure login and logout events are collected"
fi

# Ensure session initiation information is collected
echo
echo -e "${RED}4.1.9${NC} Ensure session initiation information is collected"
rhel_4_1_9_temp_1="$(egrep "^-w\s+/var/run/utmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_9_temp_1=$?
rhel_4_1_9_temp_2="$(egrep "^-w\s+/var/log/wtmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_9_temp_2=$?
rhel_4_1_9_temp_3="$(egrep "^-w\s+/var/log/btmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_9_temp_3=$?
if [[ "$rhel_4_1_9_temp_1" -eq 0 ]] && [[ "$rhel_4_1_9_temp_2" -eq 0 ]] && [[ "$rhel_4_1_9_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure session initiation information is collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure session initiation information is collected"
fi

# Ensure discretionary access control permission modification events are collected
echo
echo -e "${RED}4.1.10${NC} Ensure discretionary access control permission modification events are collected"
rhel_4_1_10_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_1=$?
rhel_4_1_10_temp_2="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_2=$?
rhel_4_1_10_temp_3="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_3=$?
rhel_4_1_10_temp_4="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_4=$?
rhel_4_1_10_temp_5="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_5=$?
rhel_4_1_10_temp_6="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_6=$?
if [[ "$rhel_4_1_10_temp_1" -eq 0 ]] && [[ "$rhel_4_1_10_temp_2" -eq 0 ]] && [[ "$rhel_4_1_10_temp_3" -eq 0 ]] && [[ "$rhel_4_1_10_temp_4" -eq 0 ]] && [[ "$rhel_4_1_10_temp_5" -eq 0 ]] && [[ "$rhel_4_1_10_temp_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure discretionary access control permission modification events are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure discretionary access control permission modification events are collected"
fi

# Ensure unsuccessful unauthorized file access attempts are collected
echo
echo -e "${RED}4.1.11${NC} Ensure unsuccessful unauthorized file access attempts are collected"
rhel_4_1_11_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_11_temp_1=$?
rhel_4_1_11_temp_2="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_11_temp_2=$?
rhel_4_1_11_temp_3="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_11_temp_3=$?
rhel_4_1_11_temp_4="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_11_temp_4=$?
if [[ "$rhel_4_1_11_temp_1" -eq 0 ]] && [[ "$rhel_4_1_11_temp_2" -eq 0 ]] && [[ "$rhel_4_1_11_temp_3" -eq 0 ]] && [[ "$rhel_4_1_11_temp_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure unsuccessful unauthorized file access attempts are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure unsuccessful unauthorized file access attempts are collected"
fi

# Ensure use of privileged commands is collected
echo
echo -e "${RED}4.1.12${NC} Ensure use of privileged commands is collected"
rhel_4_1_12_temp=0
for file in `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f`; do egrep -q "^\s*-a\s+(always,exit|exit,always)\s+-F\s+path=$file\s+-F\s+perm=x\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged\s*(#.*)?$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=$file -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/audit.rules;  ((rhel_4_1_12_temp=rhel_4_1_12_temp+1)); done
rhel_4_1_12_temp_2="$( ls -1q / | wc -l)"
if [[ "$rhel_4_1_12_temp" -ge "$rhel_4_1_12_temp_2" ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure use of privileged commands is collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure use of privileged commands is collected"
fi

# Ensure successful file system mounts are collected
echo
echo -e "${RED}4.1.13${NC} Ensure successful file system mounts are collected"
rhel_4_1_13_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_13_temp_1=$?
rhel_4_1_13_temp_2="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_13_temp_2=$?
if [[ "$rhel_4_1_13_temp_1" -eq 0 ]] && [[ "$rhel_4_1_13_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure successful file system mounts are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure successful file system mounts are collected"
fi

# Ensure file deletion events by users are collected
echo
echo -e "${RED}4.1.14${NC} Ensure file deletion events by users are collected"
rhel_4_1_14_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_14_temp_1=$?
rhel_4_1_14_temp_2="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_14_temp_2=$?
if [[ "$rhel_4_1_14_temp_1" -eq 0 ]] && [[ "$rhel_4_1_14_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure file deletion events by users are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure file deletion events by users are collected"
fi

# Ensure changes to system administration scope (sudoers) is collected
echo
echo -e "${RED}4.1.15${NC} Ensure changes to system administration scope (sudoers) is collected"
rhel_4_1_15_temp_1="$(egrep "^-w\s+/etc/sudoers\s+-p\s+wa\s+-k\s+scope\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_15_temp_1=$?
rhel_4_1_15_temp_2="$(egrep "^-w\s+/etc/sudoers.d\s+-p\s+wa\s+-k\s+scope\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_15_temp_2=$?
if [[ "$rhel_4_1_15_temp_1" -eq 0 ]] && [[ "$rhel_4_1_15_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure changes to system administration scope (sudoers) is collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure changes to system administration scope (sudoers) is collected"
fi

# Ensure system administrator actions (sudolog) are collected
echo
echo -e "${RED}4.1.16${NC} Ensure system administrator actions (sudolog) are collected"
rhel_4_1_16="$(egrep "^-w\s+/var/log/sudo.log\s+-p\s+wa\s+-k\s+actions\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_16=$?
if [[ "$rhel_4_1_16" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure system administrator actions (sudolog) are collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure system administrator actions (sudolog) are collected"
fi

# Ensure kernel module loading and unloading is collected
echo
echo -e "${RED}4.1.17${NC} Ensure kernel module loading and unloading is collected"
rhel_4_1_17_temp_1="$(egrep "^-w\s+/sbin/insmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_1=$?
rhel_4_1_17_temp_2="$(egrep "^-w\s+/sbin/rmmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_2=$?
rhel_4_1_17_temp_3="$(egrep "^-w\s+/sbin/modprobe\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_3=$?
rhel_4_1_17_temp_4="$(uname -p | grep -q 'x86_64' || egrep "^-a\s+(always,exit|exit,always)\s+arch=b32\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_4=$?
rhel_4_1_17_temp_5="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+arch=b64\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_5=$?
if [[ "$rhel_4_1_17_temp_1" -eq 0 ]] && [[ "$rhel_4_1_17_temp_2" -eq 0 ]] && [[ "$rhel_4_1_17_temp_3" -eq 0 ]] && [[ "$rhel_4_1_17_temp_4" -eq 0 ]] && [[ "$rhel_4_1_17_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure kernel module loading and unloading is collected"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure kernel module loading and unloading is collected"
fi

# Ensure the audit configuration is immutable
echo
echo -e "${RED}4.1.18${NC} Ensure the audit configuration is immutable"
rhel_4_1_18="$(egrep "^-e\s+2\s*$" /etc/audit/rules.d/audit.rules || echo "-e 2" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_18=$?
if [[ "$rhel_4_1_18" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure the audit configuration is immutable"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the audit configuration is immutable"
fi

echo -e "${BLUE}5. RHEL 7 - Access, Authentication and Authorization ${NC}"

# Ensure cron daemon is enabled
echo
echo -e "${RED}5.1.1${NC} Ensure cron daemon is enabled"
rhel_5_1_1="$(systemctl enable crond.service)"
rhel_5_1_1=$?
if [[ "$rhel_5_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure cron daemon is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure cron daemon is enabled"
fi

# Ensure permissions on /etc/crontab are configured
echo
echo -e "${RED}5.1.2${NC} Ensure permissions on /etc/crontab are configured"
rhel_5_1_2="$(chmod g-r-w-x,o-r-w-x /etc/crontab)"
rhel_5_1_2=$?
if [[ "$rhel_5_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/crontab are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/crontab are configured"
fi

# Ensure permissions on /etc/cron.hourly are configured
echo
echo -e "${RED}5.1.3${NC} Ensure permissions on /etc/cron.hourly are configured"
rhel_5_1_3="$(chmod g-r-w-x,o-r-w-x /etc/cron.hourly)"
rhel_5_1_3=$?
if [[ "$rhel_5_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.hourly are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.hourly are configured"
fi

# Ensure permissions on /etc/cron.daily are configured
echo
echo -e "${RED}5.1.4${NC} Ensure permissions on /etc/cron.daily are configured"
rhel_5_1_4="$(chmod g-r-w-x,o-r-w-x /etc/cron.daily)"
rhel_5_1_4=$?
if [[ "$rhel_5_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.daily are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.daily are configured"
fi

# Ensure permissions on /etc/cron.weekly are configured
echo
echo -e "${RED}5.1.5${NC} Ensure permissions on /etc/cron.weekly are configured"
rhel_5_1_5="$(chmod g-r-w-x,o-r-w-x /etc/cron.weekly)"
rhel_5_1_5=$?
if [[ "$rhel_5_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.weekly are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.weekly are configured"
fi

# Ensure permissions on /etc/cron.monthly are configured
echo
echo -e "${RED}5.1.6${NC} Ensure permissions on /etc/cron.monthly are configured"
rhel_5_1_6="$(chmod g-r-w-x,o-r-w-x /etc/cron.monthly)"
rhel_5_1_6=$?
if [[ "$rhel_5_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.monthly are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.monthly are configured"
fi

# Ensure permissions on /etc/cron.d are configured
echo
echo -e "${RED}5.1.7${NC} Ensure permissions on /etc/cron.d are configured enabled"
rhel_5_1_7="$(chmod g-r-w-x,o-r-w-x /etc/cron.d)"
rhel_5_1_7=$?
if [[ "$rhel_5_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.d are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.d are configured"
fi

# Ensure at/cron is restricted to authorized users
echo
echo -e "${RED}5.1.8${NC} Ensure at/cron is restricted to authorized users"
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
rhel_5_1_8_temp_1="$(chmod g-r-w-x,o-r-w-x /etc/cron.allow)"
rhel_5_1_8_temp_1=$?
rhel_5_1_8_temp_2="$(chmod g-r-w-x,o-r-w-x /etc/at.allow)"
rhel_5_1_8_temp_2=$?
if [[ "$rhel_5_1_8_temp_1" -eq 0 ]] && [[ "$rhel_5_1_8_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure at/cron is restricted to authorized users"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure at/cron is restricted to authorized users"
fi

# Ensure permissions on /etc/ssh/sshd_config are configured
echo
echo -e "${RED}5.2.1${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
rhel_5_2_1="$(chmod g-r-w-x,o-r-w-x /etc/ssh/sshd_config)"
rhel_5_2_1=$?
if [[ "$rhel_5_2_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
fi

# Ensure SSH Protocol is set to 2
echo
echo -e "${RED}5.2.2${NC} Ensure SSH Protocol is set to 2"
rhel_5_2_2="$(egrep -q "^(\s*)Protocol\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Protocol\s+\S+(\s*#.*)?\s*$/\1Protocol 2\2/" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config)"
rhel_5_2_2=$?
if [[ "$rhel_5_2_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Protocol is set to 2"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Protocol is set to 2"
fi

# Ensure SSH LogLevel is set to INFO
echo
echo -e "${RED}5.2.3${NC} Ensure SSH LogLevel is set to INFO"
rhel_5_2_3="$(egrep -q "^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$/\1LogLevel INFO\2/" /etc/ssh/sshd_config || echo "LogLevel INFO" >> /etc/ssh/sshd_config)"
rhel_5_2_3=$?
if [[ "$rhel_5_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH LogLevel is set to INFO"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LogLevel is set to INFO"
fi

# Ensure SSH X11 forwarding is disabled
echo
echo -e "${RED}5.2.4${NC} Ensure SSH X11 forwarding is disabled"
rhel_5_2_4="$(egrep -q "^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$/\1X11Forwarding no\2/" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config)"
rhel_5_2_4=$?
if [[ "$rhel_5_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH X11 forwarding is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH X11 forwarding is disabled"
fi

# Ensure SSH MaxAuthTries is set to 4 or less
echo
echo -e "${RED}5.2.5${NC} Ensure SSH MaxAuthTries is set to 4 or less"
rhel_5_2_5="$(egrep -q "^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$/\1MaxAuthTries 4\2/" /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config)"
rhel_5_2_5=$?
if [[ "$rhel_5_2_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
fi

# Ensure SSH IgnoreRhosts is enabled
echo
echo -e "${RED}5.2.6${NC} Ensure SSH IgnoreRhosts is enabled"
rhel_5_2_6="$(egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config)"
rhel_5_2_6=$?
if [[ "$rhel_5_2_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH IgnoreRhosts is enabled"
fi

# Ensure SSH HostbasedAuthentication is disabled
echo
echo -e "${RED}5.2.7${NC} Ensure SSH HostbasedAuthentication is disabled"
rhel_5_2_7="$(egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config)"
rhel_5_2_7=$?
if [[ "$rhel_5_2_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH HostbasedAuthentication is disabled"
fi

# Ensure SSH root login is disabled
echo
echo -e "${RED}5.2.8${NC} Ensure SSH root login is disabled"
rhel_5_2_8="$(egrep -q "^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$/\1PermitRootLogin no\2/" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config)"
rhel_5_2_8=$?
if [[ "$rhel_5_2_8" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH root login is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH root login is disabled"
fi

# Ensure SSH PermitEmptyPasswords is disabled
echo
echo -e "${RED}5.2.9${NC} Ensure SSH PermitEmptyPasswords is disabled"
rhel_5_2_9="$(egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config)"
rhel_5_2_9=$?
if [[ "$rhel_5_2_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitEmptyPasswords is disabled"
fi

# Ensure SSH PermitUserEnvironment is disabled
echo
echo -e "${RED}5.2.10${NC} Ensure SSH PermitUserEnvironment is disable"
rhel_5_2_10="$(egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config)"
rhel_5_2_10=$?
if [[ "$rhel_5_2_10" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disable"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitUserEnvironment is disable"
fi

# Ensure only approved MAC algorithms are used
echo
echo -e "${RED}5.2.11${NC} Ensure only approved MAC algorithms are used"
rhel_5_2_11="$(egrep -q "^(\s*)MACs\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MACs\s+\S+(\s*#.*)?\s*$/\MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\2/" /etc/ssh/sshd_config || echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config)"
rhel_5_2_11=$?
if [[ "$rhel_5_2_11" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure only approved MAC algorithms are used"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure only approved MAC algorithms are used"
fi


# Ensure SSH Idle Timeout Interval is configured
echo
echo -e "${RED}5.2.12${NC} Ensure SSH Idle Timeout Interval is configured"
rhel_5_2_12_temp_1="$(egrep -q "^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\1ClientAliveInterval 300\2/" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config)"
rhel_5_2_12_temp_1=$?
rhel_5_2_12_temp_2="$(egrep -q "^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\1ClientAliveCountMax 3\2/" /etc/ssh/sshd_config || echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config)"
rhel_5_2_12_temp_2=$?
if [[ "$rhel_5_2_12_temp_1" -eq 0 ]] && [[ "$rhel_5_2_12_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Idle Timeout Interval is configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Idle Timeout Interval is configured"
fi

# Ensure SSH LoginGraceTime is set to one minute or less
echo
echo -e "${RED}5.2.13${NC} Ensure SSH LoginGraceTime is set to one minute or less"
rhel_5_2_13="$(egrep -q "^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$/\1LoginGraceTime 60\2/" /etc/ssh/sshd_config || echo "LoginGraceTime 60" >> /etc/ssh/sshd_config)"
rhel_5_2_13=$?
if [[ "$rhel_5_2_13" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
fi

# Ensure SSH warning banner is configured
echo
echo -e "${RED}5.2.15${NC} Ensure SSH warning banner is configured"
rhel_5_2_15="$(egrep -q "^(\s*)Banner\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Banner\s+\S+(\s*#.*)?\s*$/\1Banner \/etc\/issue.net\2/" /etc/ssh/sshd_config || echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config)"
rhel_5_2_15=$?
if [[ "$rhel_5_2_15" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH warning banner is configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH warning banner is configured"
fi

# Ensure password creation requirements are configured
echo
echo -e "${RED}5.3.1${NC} Ensure password creation requirements are configured"
rhel_5_3_1_temp_1="$(egrep -q "^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$/\minlen=14\2/" /etc/security/pwquality.conf || echo "minlen=14" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_1=$?
rhel_5_3_1_temp_2="$(egrep -q "^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$/\dcredit=-1\2/" /etc/security/pwquality.conf || echo "dcredit=-1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_2=$?
rhel_5_3_1_temp_3="$(egrep -q "^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$/\ucredit=-1\2/" /etc/security/pwquality.conf || echo "ucredit=-1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_3=$?
rhel_5_3_1_temp_4="$(egrep -q "^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$/\ocredit=-1\2/" /etc/security/pwquality.conf || echo "ocredit=-1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_4=$?
rhel_5_3_1_temp_5="$(egrep -q "^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$/\lcredit=-1\2/" /etc/security/pwquality.conf || echo "lcredit=-1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_5=$?
rhel_5_3_1_temp_6="$(echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/system-auth)"
rhel_5_3_1_temp_6=$?
rhel_5_3_1_temp_7="$(echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/password-auth)"
rhel_5_3_1_temp_7=$?
if [[ "$rhel_5_3_1_temp_1" -eq 0 ]] && [[ "$rhel_5_3_1_temp_2" -eq 0 ]] && [[ "$rhel_5_3_1_temp_3" -eq 0 ]] && [[ "$rhel_5_3_1_temp_4" -eq 0 ]] && [[ "$rhel_5_3_1_temp_5" -eq 0 ]] && [[ "$rhel_5_3_1_temp_6" -eq 0 ]] && [[ "$rhel_5_3_1_temp_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password creation requirements are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password creation requirements are configured"
fi

# Ensure password reuse is limited
echo
echo -e "${RED}5.3.3${NC} Ensure password reuse is limited"
rhel_5_3_3_temp_1="$(egrep -q "^\s*password\s+sufficient\s+pam_unix.so(\s+.*)$" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+remember=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1remember=5 \2/ }' /etc/pam.d/system-auth && sed -ri 's/(^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*\s+)remember=[0-9]+(\s+.*)?$/\1remember=5\3/' /etc/pam.d/system-auth || echo Ensure\ password\ reuse\ is\ limited - /etc/pam.d/system-auth not configured.)"
rhel_5_3_3_temp_1=$?
rhel_5_3_3_temp_2="$(egrep -q "^\s*password\s+sufficient\s+pam_unix.so(\s+.*)$" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+remember=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1remember=5 \2/ }' /etc/pam.d/password-auth && sed -ri 's/(^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*\s+)remember=[0-9]+(\s+.*)?$/\1remember=5\3/' /etc/pam.d/password-auth || echo Ensure\ password\ reuse\ is\ limited - /etc/pam.d/password-auth not configured.)"
rhel_5_3_3_temp_2=$?
if [[ "$rhel_5_3_3_temp_1" -eq 0 ]] && [[ "$rhel_5_3_3_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password reuse is limited"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password reuse is limited"
fi

# Ensure password hashing algorithm is SHA-512
echo
echo -e "${RED}5.3.4${NC} Ensure password hashing algorithm is SHA-512"
rhel_5_3_4_temp_1="$(egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/system-auth || echo Ensure\ password\ hashing\ algorithm\ is\ SHA-512 - /etc/pam.d/password-auth not configured.)"
rhel_5_3_4_temp_1=$?
rhel_5_3_4_temp_2="$(egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/password-auth || echo Ensure\ password\ hashing\ algorithm\ is\ SHA-512 - /etc/pam.d/password-auth not configured.)"
rhel_5_3_4_temp_2=$?
if [[ "$rhel_5_3_4_temp_1" -eq 0 ]] && [[ "$rhel_5_3_4_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password hashing algorithm is SHA-512"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password hashing algorithm is SHA-512"
fi

# Ensure password expiration is 90 days or less
echo
echo -e "${RED}5.4.1.1${NC} Ensure password expiration is 90 days or less"
rhel_5_4_1_1="$(egrep -q "^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 90\2/" /etc/login.defs || echo "PASS_MAX_DAYS 90" >> /etc/login.defs)"
rhel_5_4_1_1=$?
getent passwd | cut -f1 -d ":" | xargs -n1 chage --maxdays 90
if [[ "$rhel_5_4_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password expiration is 90 days or less"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password expiration is 90 days or less"
fi

# Ensure minimum days between password changes is 7 or more
echo
echo -e "${RED}5.4.1.2${NC} Ensure minimum days between password changes is 7 or more"
rhel_5_4_1_2="$(egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 7\2/" /etc/login.defs || echo "PASS_MIN_DAYS 7" >> /etc/login.defs)"
rhel_5_4_1_2=$?
getent passwd | cut -f1 -d ":" | xargs -n1 chage --mindays 7
if [[ "$rhel_5_4_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is 7 or more"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure minimum days between password changes is 7 or more"
fi

# Ensure password expiration warning days is 7 or more
echo
echo -e "${RED}5.4.1.3${NC} Ensure password expiration warning days is 7 or more"
rhel_5_4_1_3="$(egrep -q "^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$/\PASS_WARN_AGE 7\2/" /etc/login.defs || echo "PASS_WARN_AGE 7" >> /etc/login.defs)"
rhel_5_4_1_3=$?
getent passwd | cut -f1 -d ":" | xargs -n1 chage --warndays 7
if [[ "$rhel_5_4_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password expiration warning days is 7 or more"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password expiration warning days is 7 or more"
fi

# Ensure inactive password lock is 30 days or less
echo
echo -e "${RED}5.4.1.4${NC} Ensure inactive password lock is 30 days or less"
rhel_5_4_1_4="$(useradd -D -f 30)"
rhel_5_4_1_4=$?
getent passwd | cut -f1 -d ":" | xargs -n1 chage --inactive 30
if [[ "$rhel_5_4_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure inactive password lock is 30 days or less"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure inactive password lock is 30 days or less"
fi

# Ensure system accounts are non-login
echo
echo "${RED}5.4.2${NC} Ensure system accounts are non-login"
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]
  then
    /usr/sbin/usermod -L $user
    if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]
    then
      /usr/sbin/usermod -s /sbin/nologin $user
    fi
  fi
done
echo -e "${GREEN}Remediated:${NC} Ensure system accounts are non-login"

# Ensure default group for the root account is GID 0
echo
echo -e "${RED}5.4.3${NC} Ensure default group for the root account is GID 0"
rhel_5_4_3="$(usermod -g 0 root)"
rhel_5_4_3=$?
if [[ "$rhel_5_4_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure default group for the root account is GID 0"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure default group for the root account is GID 0"
fi

# Ensure default user umask is 027 or more restrictive
echo
echo -e "${RED}5.4.4${NC} Ensure default user umask is 027 or more restrictive"
rhel_5_4_4_temp_1="$(egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/bashrc && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/bashrc || echo "umask 077" >> /etc/bashrc)"
rhel_5_4_4_temp_1=$?
rhel_5_4_4_temp_2="$(egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/profile || echo "umask 077" >> /etc/profile)"
rhel_5_4_4_temp_2=$?
if [[ "$rhel_5_4_4_temp_1" -eq 0 ]] && [[ "$rhel_5_4_4_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure default user umask is 027 or more restrictive"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure default user umask is 027 or more restrictive"
fi

# Ensure access to the su command is restricted
echo
echo -e "${RED}5.6${NC} Ensure access to the su command is restricted"
rhel_5_6="$(egrep -q "^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$" /etc/pam.d/su && sed -ri '/^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$/ { /^\s*auth\s+required\s+pam_wheel.so(\s+\S+)*(\s+use_uid)(\s+.*)?$/! s/^(\s*auth\s+required\s+pam_wheel.so)(\s+.*)?$/\1 use_uid\2/ }' /etc/pam.d/su || echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su)"
rhel_5_6=$?
if [[ "$rhel_5_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure access to the su command is restricted"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure access to the su command is restricted"
fi

echo -e "${BLUE}6. RHEL 7 - System Maintenance ${NC}"

# Ensure permissions on /etc/passwd are configured
echo
echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
rhel_6_1_2="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/passwd)"
rhel_6_1_2=$?
if [[ "$rhel_6_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are configured"
fi

# Ensure permissions on /etc/shadow are configured
echo
echo -e "${RED}6.1.3${NC} Ensure permissions on /etc/shadow are configured"
rhel_6_1_3="$(chmod -t,u-x-s,g-w-x-s,o-r-w-x /etc/shadow)"
rhel_6_1_3=$?
if [[ "$rhel_6_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow are configured"
fi

# Ensure permissions on /etc/group are configured
echo
echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
rhel_6_1_4="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/group)"
rhel_6_1_4=$?
if [[ "$rhel_6_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are configured"
fi

# Ensure permissions on /etc/gshadow are configured
echo
echo -e "${RED}6.1.5${NC} Ensure permissions on /etc/gshadow are configured"
rhel_6_1_5="$(chmod -t,u-x-s,g-w-x-s,o-r-w-x /etc/gshadow)"
rhel_6_1_5=$?
if [[ "$rhel_6_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow are configured"
fi

# Ensure permissions on /etc/passwd- are configured
echo
echo -e "${RED}6.1.6${NC} Ensure permissions on /etc/passwd- are configured"
rhel_6_1_6="$(chmod -t,u-x-s,g-r-w-x-s,o-r-w-x /etc/passwd-)"
rhel_6_1_6=$?
if [[ "$rhel_6_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd- are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd- are configured"
fi

# Ensure permissions on /etc/shadow- are configured
echo
echo -e "${RED}6.1.7${NC} Ensure permissions on /etc/shadow- are configured"
rhel_6_1_7="$(chmod -t,u-x-s,g-r-w-x-s,o-r-w-x /etc/shadow-)"
rhel_6_1_7=$?
if [[ "$rhel_6_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow- are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow- are configured"
fi

# Ensure permissions on /etc/group- are configured
echo
echo -e "${RED}6.1.8${NC} Ensure permissions on /etc/group- are configured"
rhel_6_1_8="$(chmod -t,u-x-s,g-r-w-x-s,o-r-w-x /etc/group-)"
rhel_6_1_8=$?
if [[ "$rhel_6_1_8" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group- are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group- are configured"
fi

# Ensure permissions on /etc/gshadow- are configured
echo
echo -e "${RED}6.1.9${NC} EEnsure permissions on /etc/gshadow- are configured"
rhel_6_1_9="$(chmod -t,u-x-s,g-r-w-x-s,o-r-w-x /etc/gshadow-)"
rhel_6_1_9=$?
if [[ "$rhel_6_1_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow- are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow- are configured"
fi

# Ensure no legacy &quot;+&quot; entries exist in /etc/passwd
echo
echo -e "${RED}6.2.2${NC} Ensure no legacy + entries exist in /etc/passwd"
rhel_6_2_2="$(sed -ri '/^\+:.*$/ d' /etc/passwd)"
rhel_6_2_2=$?
if [[ "$rhel_6_2_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy + entries exist in /etc/passwd"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy + entries exist in /etc/passwd"
fi

# Ensure no legacy &quot;+&quot; entries exist in /etc/shadow
echo
echo -e "${RED}6.2.3${NC} Ensure no legacy + entries exist in /etc/shadow"
rhel_6_2_3="$(sed -ri '/^\+:.*$/ d' /etc/shadow)"
rhel_6_2_3=$?
if [[ "$rhel_6_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy + entries exist in /etc/shadowd"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy + entries exist in /etc/shadowd"
fi

# Ensure no legacy &quot;+&quot; entries exist in /etc/group
echo
echo -e "${RED}6.2.4${NC} Ensure no legacy + entries exist in /etc/group"
rhel_6_2_4="$(sed -ri '/^\+:.*$/ d' /etc/group)"
rhel_6_2_4=$?
if [[ "$rhel_6_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy + entries exist in /etc/group"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy + entries exist in /etc/group"
fi
