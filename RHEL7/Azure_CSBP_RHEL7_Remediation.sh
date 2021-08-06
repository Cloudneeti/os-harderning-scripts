#!/bin/bash

: '
#SYNOPSIS
    Quick win script for remediation of RHEL Linux 7 baseline misconfigurations.
.DESCRIPTION
    This script aims to remediate OS baseline misconfigurations for RHEL Linux 7 based Virtual machines on Azure.
    **Total policies supported: 27

.NOTES

    Copyright (c) ZCSPM. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 1.0
    # PREREQUISITE

.EXAMPLE
    Ensure that you are logged in as root user. Use su command for the same.
    Command to execute : bash Azure_CSBP_RHEL7_Remediation.sh
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

yum update -y && yum install wget -y

############################################################################################################################

##Category 2 Azure RHEL - Services
echo
echo -e "${BLUE}2 Azure RHEL - Services${NC}"

# The portmap service should be disabled.
echo
echo -e "${RED}CCE-4550-0${NC} The portmap service should be disabled"
rhel_temp="$(rpm -qa | grep portmap && yum erase portmap -y)"
rhel_temp=$?
if [[ "$rhel_temp" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The portmap service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The portmap service should be disabled"
  fail=$((fail + 1))
fi

# Zeroconf networking should be disabled.
echo
echo -e "${RED}CCE-14054-1${NC} Zeroconf networking should be disabled"
rhel_temp="$(echo "NOZEROCONF=no" >>  /etc/sysconfig/network)"
rhel_temp=$?
if [[ "$rhel_temp" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Zeroconf networking should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Zeroconf networking should be disabled"
  fail=$((fail + 1))
fi

# The kdump service should be disabled
echo
echo -e "${RED}CCE-3425-6${NC} The kdump service should be disabled."
rhel_temp="$(systemctl start kdump.service ||  yum erase -y kexec-tools)"
rhel_temp=$?
if [[ "$rhel_temp" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The kdump service should be disabled."
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The kdump service should be disabled."
  fail=$((fail + 1))
fi

# The isdnutils-base package should be uninstalled.
echo
echo -e "${RED}CCE-14825-4${NC} The isdnutils-base package should be uninstalled.."
rhel_temp="$(yum erase -y isdn4k-utils)"
rhel_temp=$?
if [[ "$rhel_temp" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The isdnutils-base package should be uninstalled.."
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The isdnutils-base package should be uninstalled.."
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 2.2 Services - Special Purpose Services
echo
echo -e "${BLUE}2.2 Services - Special Purpose Services${NC}"

# Ensure Avahi Server is not enabled
echo
echo -e "${RED}2.2.3${NC} Ensure Avahi Server is not enabled"
rhel_2_2_3="$(systemctl disable avahi-daemon.service || yum erase avahi -y)"
rhel_2_2_3=$?
if [[ "$rhel_2_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Avahi Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Avahi Server is not enabled"
  fail=$((fail + 1))
fi

# Ensure CUPS is not enabled
echo
echo -e "${RED}2.2.4${NC} Ensure CUPS is not enabled"
rhel_2_2_4="$(systemctl disable cups.service  || yum erase cups -y)"
rhel_2_2_4=$?
if [[ "$rhel_2_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure CUPS is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure CUPS is not enabled"
  fail=$((fail + 1))
fi

# Ensure DHCP Server is not enabled
echo
echo -e "${RED}2.2.5${NC} Ensure DHCP Server is not enabled"
rhel_2_2_5="$(systemctl disable dhcpd.service || yum erase dhcpd -y)"
rhel_2_2_5=$?
if [[ "$rhel_2_2_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DHCP Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DHCP Server is not enabled"
  fail=$((fail + 1))
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
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NFS and RPC are not enabled"
  fail=$((fail + 1))
fi

# Ensure SNMP Server is not enabled
echo
echo -e "${RED}2.2.14${NC} Ensure SNMP Server is not enabled"
rhel_2_2_14="$(systemctl disable snmpd.service || yum erase snmpd -y)"
rhel_2_2_14=$?
if [[ "$rhel_2_2_14" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SNMP Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SNMP Server is not enabled"
  fail=$((fail + 1))
fi

# Ensure NIS Server is not enabled
echo
echo -e "${RED}2.2.16${NC} Ensure NIS Server is not enabled"
rhel_2_2_16="$(systemctl disable ypserv.service || yum erase ypserv -y)"
rhel_2_2_16=$?
if [[ "$rhel_2_2_16" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NIS Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NIS Server is not enabled"
  fail=$((fail + 1))
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
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh server is not enabled"
  fail=$((fail + 1))
fi

# Ensure rsync service is not enabled
echo
echo -e "${RED}2.2.21${NC} Ensure rsync service is not enabled"
rhel_2_2_21="$(systemctl disable rsyncd.service || yum erase rsyncd -y)"
rhel_2_2_21=$?
if [[ "$rhel_2_2_21" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsync service is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsync service is not enabled"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 2.3 Services - Service Clients
echo
echo -e "${BLUE}2.3 Services - Service Clients${NC}"

# Ensure rsh client is not installed
echo
echo -e "${RED}2.3.2${NC} Ensure rsh client is not installed"
rhel_2_3_2="$(rpm -q rsh && yum -y erase rsh)"
rhel_2_3_2=$?
if [[ "$rhel_2_3_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsh client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh client is not installed"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 3.2 Network Configuration - Network Parameters (Host and Router)
echo
echo -e "${BLUE}3.2 Network Configuration - Network Parameters (Host and Router)${NC}"

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
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure source routed packets are not accepted"
  fail=$((fail + 1))
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
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure broadcast ICMP requests are ignored"
  fail=$((fail + 1))
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
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Reverse Path Filtering is enabled"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 3.5 Network Configuration - Uncommon Network Protocols
echo
echo -e "${BLUE}3.5 Network Configuration - Uncommon Network Protocols${NC}"

# Ensure RDS is disabled
echo
echo -e "${RED}3.5.3${NC} Ensure RDS is disabled"
rhel_3_5_3="$(modprobe -n -v rds | grep "^install /bin/true$" || echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_3=$?
lsmod | egrep "^rds\s" && rmmod rds
if [[ "$rhel_3_5_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure RDS is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure RDS is disabled"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 4.1 Logging and Auditing - Configure System Accounting (auditd)
echo
echo -e "${BLUE}4.1 Logging and Auditing - Configure System Accounting (auditd)${NC}"

# Ensure auditd package is installed
echo
echo -e "${RED}4.1.2${NC} Ensure auditd package is installed"
rhel_4_1_2="$(yum install -y auditd && systemctl enable auditd.service)"
rhel_4_1_2=$?
if [[ "$rhel_4_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure auditd package is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure auditd package is installed"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 4.2 Logging and Auditing - Configure rsyslog
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure rsyslog${NC}"

# Ensure syslog-ng service is enabled
echo
echo -e "${RED}4.2.2.1${NC} Ensure syslog-ng service is enabled"
rhel_4_2_2_1="$(rpm -q syslog-ng && systemctl enable syslog-ng.service)"
rhel_4_2_2_1=$?
if [[ "$rhel_4_2_2_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure syslog-ng service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure syslog-ng service is enabled"
  fail=$((fail + 1))
fi

# Ensure rsyslog or syslog-ng is installed
echo
echo -e "${RED}4.2.3${NC} Ensure rsyslog or syslog-ng is installed"
rhel_4_2_3="$(rpm -q rsyslog || rpm -q syslog-ng || yum -y install rsyslog)"
rhel_4_2_3=$?
if [[ "$rhel_4_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog or syslog-ng is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog or syslog-ng is installed"
  fail=$((fail + 1))
fi

# Ensure permissions on all logfiles are configured
echo
echo -e "${RED}4.2.4${NC} Ensure permissions on all logfiles are configured"
rhel_4_2_4="$(chmod -R g-w-x,o-r-w-x /var/log/*)"
rhel_4_2_4=$?
if [[ "$rhel_4_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on all logfiles are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on all logfiles are configuredd"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 5.1 Access, Authentication and Authorization - Configure cron
echo
echo -e "${BLUE}5.1 Access, Authentication and Authorization - Configure cron${NC}"

# Ensure cron daemon is enabled
echo
echo -e "${RED}5.1.1${NC} Ensure cron daemon is enabled"
rhel_5_1_1="$(systemctl enable crond.service)"
rhel_5_1_1=$?
if [[ "$rhel_5_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure cron daemon is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure cron daemon is enabled"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category 5.2 Access, Authentication and Authorization - SSH Server Configuration
echo
echo -e "${BLUE}5.2 Access, Authentication and Authorization - SSH Server Configuration${NC}"

# Ensure SSH HostbasedAuthentication is disabled
echo
echo -e "${RED}5.2.7${NC} Ensure SSH HostbasedAuthentication is disabled"
rhel_5_2_7="$(egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config)"
rhel_5_2_7=$?
if [[ "$rhel_5_2_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH HostbasedAuthentication is disabled"
  fail=$((fail + 1))
fi

# Ensure SSH PermitEmptyPasswords is disabled
echo
echo -e "${RED}5.2.9${NC} Ensure SSH PermitEmptyPasswords is disabled"
rhel_5_2_9="$(egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config)"
rhel_5_2_9=$?
if [[ "$rhel_5_2_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  fail=$((fail + 1))
fi

# Ensure SSH Protocol is set to 2
echo
echo -e "${RED}5.2.2${NC} Ensure SSH Protocol is set to 2"
rhel_5_2_2="$(egrep -q "^(\s*)Protocol\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Protocol\s+\S+(\s*#.*)?\s*$/\1Protocol 2\2/" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config)"
rhel_5_2_2=$?
if [[ "$rhel_5_2_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Protocol is set to 2"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Protocol is set to 2"
  fail=$((fail + 1))
fi

# Ensure SSH MaxAuthTries is set to 4 or less
echo
echo -e "${RED}5.2.5${NC} Ensure SSH MaxAuthTries is set to 4 or less"
rhel_5_2_5="$(egrep -q "^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$/\1MaxAuthTries 4\2/" /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config)"
rhel_5_2_5=$?
if [[ "$rhel_5_2_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  fail=$((fail + 1))
fi

# Ensure SSH IgnoreRhosts is enabled
echo
echo -e "${RED}5.2.6${NC} Ensure SSH IgnoreRhosts is enabled"
rhel_5_2_6="$(egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config)"
rhel_5_2_6=$?
if [[ "$rhel_5_2_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH IgnoreRhosts is enabled"
  fail=$((fail + 1))
fi

# Ensure SSH PermitUserEnvironment is disabled
echo
echo -e "${RED}5.2.10${NC} Ensure SSH PermitUserEnvironment is disable"
rhel_5_2_10="$(egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config)"
rhel_5_2_10=$?
if [[ "$rhel_5_2_10" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disable"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitUserEnvironment is disable"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 5.4 Access, Authentication and Authorization - User Accounts and Environment
echo
echo -e "${BLUE}5.4 Access, Authentication and Authorization - User Accounts and Environment${NC}"

# Ensure minimum days between password changes is 7 or more
echo
echo -e "${RED}5.4.1.2${NC} Ensure minimum days between password changes is 7 or more"
rhel_5_4_1_2="$(egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 7\2/" /etc/login.defs || echo "PASS_MIN_DAYS 7" >> /etc/login.defs)"
rhel_5_4_1_2=$?
getent passwd | cut -f1 -d ":" | xargs -n1 chage --mindays 7
if [[ "$rhel_5_4_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is 7 or more"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure minimum days between password changes is 7 or more"
  fail=$((fail + 1))
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
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password hashing algorithm is SHA-512"
  fail=$((fail + 1))
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

###########################################################################################################################

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"

# Ensure permissions on /etc/passwd are configured
echo
echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
rhel_6_1_2="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/passwd)"
rhel_6_1_2=$?
if [[ "$rhel_6_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/group are configured
echo
echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
rhel_6_1_4="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/group)"
rhel_6_1_4=$?
if [[ "$rhel_6_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are configured"
  fail=$((fail + 1))
fi

############################################################################################################################

echo
echo -e "${GREEN}Remediation script for RHEL Linux 7 executed successfully!!${NC}"
echo
echo -e "${YELLOW}Summary:${NC}"
echo -e "${YELLOW}Remediation Passed:${NC} $success" 
echo -e "${YELLOW}Remediation Failed:${NC} $fail"

###########################################################################################################################