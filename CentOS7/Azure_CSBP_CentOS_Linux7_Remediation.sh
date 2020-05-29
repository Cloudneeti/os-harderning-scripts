#!/bin/bash

: '
#SYNOPSIS
    Quick win script for remediation of CentOS Linux 7 baseline misconfigurations.
.DESCRIPTION
    This script will remediation 40 OS baseline misconfigurations for CentOS Linux 7 based Virtual machines on Azure.
    **Total policies supported: 27

.NOTES

    Copyright (c) Cloudneeti. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 1.0
    # PREREQUISITE

.EXAMPLE
    Ensure that you are logged in as root user. Use su command for the same.
    Command to execute : bash Azure_CSBP_CentOS_Linux7_Remediation.sh
.INPUTS

.OUTPUTS
    None
'

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'

###########################################################################################################################

##Category 1.5 Initial Setup - Additional Process Hardening
echo
echo -e "${BLUE}1.5 Initial Setup - Additional Process Hardening${NC}"

#Ensure address space layout randomization (ASLR) is enabled
echo
echo -e "${RED}1.5.3${NC} Ensure address space layout randomization (ASLR) is enabled"
egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure address space layout randomization (ASLR) is enabled"
fi

############################################################################################################################

##Category 2.2 Services - Special Purpose Services
echo
echo -e "${BLUE}2.2 Services - Special Purpose Services${NC}"

#Ensure Avahi Server is not enabled
echo
echo -e "${RED}2.2.3${NC} Ensure Avahi Server is not enabled"
systemctl disable avahi-daemon
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Avahi Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Avahi Server is not enabled"
fi

#Ensure CUPS is not enabled
echo
echo -e "${RED}2.2.4${NC} Ensure CUPS is not enabled"
systemctl disable cups
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure CUPS is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure CUPS is not enabled"
fi
 
#Ensure DHCP Server is not enabled
echo
echo -e "${RED}2.2.5${NC} Ensure DHCP Server is not enabled"
systemctl disable dhcpd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DHCP Server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DHCP Server is not enabled"
fi

#Ensure rsh server is not enabled
echo
echo -e "${RED}2.2.17${NC} Ensure rsh server is not enabled"
systemctl disable rsh.socket.service && systemctl disable rlogin.socket.service && systemctl disable rexec.socket.service
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsh server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh server is not enabled"
fi
 
#Ensure telnet server is not enabled
echo
echo -e "${RED}2.2.18${NC} Ensure telnet server is not enabled"
systemctl disable telnet.socket.service
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure telnet server is not enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure telnet server is not enabled"
fi

###########################################################################################################################

##Category 2.3 Services - Service Clients
echo
echo -e "${BLUE}2.3 Services - Service Clients${NC}"

#Ensure rsh client is not installed
echo
echo -e "${RED}2.3.2${NC} Ensure rsh client is not installed"
yum remove rsh
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsh client is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh client is not installed"
fi

#Ensure telnet client is not installed
echo
echo -e "${RED}2.3.4${NC} Ensure telnet client is not installed"
yum -y remove telnet
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure telnet client is not installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure telnet client is not installed"
fi

###########################################################################################################################

##Category 3.1 Network Configuration - Network Parameters (Host Only)
echo
echo -e "${BLUE}3.1 Network Configuration - Network Parameters (Host Only)${NC}"

#Ensure IP forwarding is disabled
echo
echo -e "${RED}3.1.1${NC} Ensure IP forwarding is disabled"
egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IP forwarding is disabled"
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

#Ensure broadcast ICMP requests are ignored
echo
echo -e "${RED}3.2.5${NC} Ensure broadcast ICMP requests are ignored"
egrep -q "^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_echo_ignore_broadcasts = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure broadcast ICMP requests are ignored"
 
#Ensure bogus ICMP responses are ignored
echo
echo -e "${RED}3.2.6${NC} Ensure bogus ICMP responses are ignored"
egrep -q "^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_ignore_bogus_error_responses = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure bogus ICMP responses are ignored"
 
#Ensure Reverse Path Filtering is enabled
echo
echo -e "${RED}3.2.7${NC} Ensure Reverse Path Filtering is enabled"
egrep -q "^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure Reverse Path Filtering is enabled"
 
#Ensure TCP SYN Cookies is enabled
echo
echo -e "${RED}3.2.8${NC} Ensure TCP SYN Cookies is enabled"
egrep -q "^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.tcp_syncookies = 1\2/" /etc/sysctl.conf || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure TCP SYN Cookies is enabled"

###########################################################################################################################

##Category 3.5 Network Configuration - Uncommon Network Protocols
echo
echo -e "${BLUE}3.5 Network Configuration - Uncommon Network Protocols${NC}"

#Ensure RDS is disabled
echo
echo -e "${RED}3.5.3${NC} Ensure RDS is disabled"
modprobe -n -v rds | grep "^install /bin/true$" || echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
policystatus=$?
lsmod | egrep "^rds\s" && rmmod rds
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure RDS is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure RDS is disabled"
fi

###########################################################################################################################

##Category 4.2 Logging and Auditing - Configure rsyslog
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure rsyslog${NC}"

#Ensure rsyslog Service is enabled
echo
echo -e "${RED}4.2.1.1${NC} Ensure rsyslog Service is enabled"
systemctl enable rsyslog
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog Service is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog Service is enabled"
fi

#Ensure rsyslog default file permissions configured
echo
echo -e "${RED}4.2.1.3${NC} Ensure rsyslog default file permissions configured"
grep "$FileCreateMode 0640" /etc/rsyslog.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.conf
grep "$FileCreateMode 0640" /etc/rsyslog.d/*.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.d/*.conf
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog default file permissions configured"
 
#Ensure remote rsyslog messages are only accepted on designated log hosts
echo
echo -e "${RED}4.2.1.5${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"
sed -i -e 's/#$ModLoad imtcp/$ModLoad imtcp/g' /etc/rsyslog.conf
grep "$ModLoad imtcp" /etc/rsyslog.conf || echo "$""ModLoad imtcp" >> /etc/rsyslog.conf
sed -i -e 's/#$InputTCPServerRun 514/$InputTCPServerRun 514/g' /etc/rsyslog.conf
grep "$InputTCPServerRun 514" /etc/rsyslog.conf || echo "$""InputTCPServerRun 514" >> /etc/rsyslog.conf
pkill -HUP rsyslogd
echo -e "${GREEN}Remediated:${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"

#Ensure rsyslog or syslog-ng is installed
echo
echo -e "${RED}4.2.3${NC} Ensure rsyslog or syslog-ng is installed"
yum install rsyslog && yum install syslog-ng
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog or syslog-ng is installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog or syslog-ng is installed"
fi

###########################################################################################################################

##Category 5.1 Access, Authentication and Authorization - Configure cron
echo
echo -e "${BLUE}5.1 Access, Authentication and Authorization - Configure cron${NC}"

#Ensure cron daemon is enabled
echo
echo -e "${RED}5.1.1${NC} Ensure cron daemon is enabled"
systemctl enable crond
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure cron daemon is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure cron daemon is enabled"
fi

###########################################################################################################################

##Category 5.2 Access, Authentication and Authorization - SSH Server Configuration
echo
echo -e "${BLUE}5.2 Access, Authentication and Authorization - SSH Server Configuration${NC}"

#Ensure SSH Protocol is set to 2
echo
echo -e "${RED}5.2.2${NC} Ensure SSH Protocol is set to 2"
egrep -q "^(\s*)Protocol\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Protocol\s+\S+(\s*#.*)?\s*$/\1Protocol 2\2/" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Protocol is set to 2"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Protocol is set to 2"
fi

#Ensure SSH IgnoreRhosts is enabled
echo
echo -e "${RED}5.2.6${NC} Ensure SSH IgnoreRhosts is enabled"
egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH IgnoreRhosts is enabled"
fi
 
#Ensure SSH HostbasedAuthentication is disabled
echo
echo -e "${RED}5.2.7${NC} Ensure SSH HostbasedAuthentication is disabled"
egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH HostbasedAuthentication is disabled"
fi

#Ensure SSH PermitEmptyPasswords is disabled
echo
echo -e "${RED}5.2.9${NC} Ensure SSH PermitEmptyPasswords is disabled"
egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitEmptyPasswords is disabled"
fi

#Ensure SSH PermitUserEnvironment is disabled
echo
echo -e "${RED}5.2.10${NC} Ensure SSH PermitUserEnvironment is disabled"
egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disabled"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitUserEnvironment is disabled"
fi

###########################################################################################################################

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"

#Ensure permissions on /etc/passwd are configured
echo
echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
chown root:root /etc/passwd && chmod 644 /etc/passwd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are configured"
fi
 
#Ensure permissions on /etc/group are configured
echo
echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
chown root:root /etc/group && chmod 644 /etc/group
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are configured"
fi

###########################################################################################################################