#!/bin/bash

: '
#SYNOPSIS
    Quick win script for remediation of Ubuntu baseline misconfigurations.
.DESCRIPTION
    This script aims to remediate all possible OS baseline misconfigurations for Ubuntu 18.04 based Virtual machines.

.NOTES

    Copyright (c) ZCSPM. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 1.0
    # PREREQUISITE

.EXAMPLE
    Command to execute : bash Azure_CSBP_Ubuntu18_04_Remediation.sh
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

##Category Initial Setup - Additional Process Hardening
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

##Category 2.1 Services - inetd Services
echo
echo -e "${BLUE}2.1 Services - inetd Services${NC}"

# 2.2.10 Ensure xinetd is not enabled
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

# 2.1.6 Ensure rsh server is not enabled
echo
echo -e "${RED}2.1.6${NC} Ensure rsh server is not enabled"
sed -i -e 's/shell/#shell/g' /etc/inetd.conf
grep "shell" /etc/inetd.conf || echo "shell" >> /etc/inetd.conf
sed -i -e 's/shell/#shell/g' /etc/inetd.d/*
grep "shell" /etc/inetd.d/* || echo "shell" >> /etc/inetd.d/*
sed -i -e 's/login/#login/g' /etc/rsyslog.conf
grep "login" /etc/inetd.conf || echo "login" >> /etc/inetd.conf
sed -i -e 's/login/#login/g' /etc/inetd.d/*
grep "login" /etc/inetd.d/* || echo "login" >> /etc/inetd.d/*
sed -i -e 's/exec/#exec/g' /etc/rsyslog.conf
grep "exec" /etc/inetd.conf || echo "exec" >> /etc/inetd.conf
sed -i -e 's/exec/#exec/g' /etc/inetd.d/*
grep "exec" /etc/inetd.d/* || echo "exec" >> /etc/inetd.d/*
echo -e "${GREEN}Remediated:${NC} Ensure rsh server is not enabled"
success=$((success + 1))

# 2.1.8 Ensure telnet server is not enabled
echo
echo -e "${RED}2.1.8${NC} Ensure telnet server is not enabled"
sed -i -e 's/telnet/#telnet/g' /etc/inetd.conf
grep "telnet" /etc/inetd.conf || echo "telnet" >> /etc/inetd.conf
sed -i -e 's/shell/#shell/g' /etc/inetd.d/*
grep "shell" /etc/inetd.d/* || echo "shell" >> /etc/inetd.d/*
echo -e "${GREEN}Remediated:${NC} Ensure telnet server is not enabled"
success=$((success + 1))

# 2.1.9 Ensure tftp server is not enabled
echo
echo -e "${RED}2.1.9${NC} Ensure tftp server is not enabled"
sed -i -e 's/tftp/#tftp/g' /etc/inetd.conf
grep "tftp" /etc/inetd.conf || echo "tftp" >> /etc/inetd.conf
sed -i -e 's/shell/#shell/g' /etc/inetd.d/*
grep "tftp" /etc/inetd.d/* || echo "tftp" >> /etc/inetd.d/*
echo -e "${GREEN}Remediated:${NC} Ensure tftp server is not enabled"
success=$((success + 1))

##Category 2.2 Services - Special Purpose Services
echo
echo -e "${BLUE}2.2 Services - Special Purpose Services${NC}"

# 2.2.11 Ensure IMAP and POP3 server is not enabled
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
systemctl disable isc-dhcp-server && systemctl disable isc-dhcp-server6
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
echo -e "${RED}2.2.17${NC} Ensure LDAP server is not enabled"
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
apt-get remove telnet
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure telnet client is not installed"
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure telnet client is not installed"
    fail=$((fail + 1))
fi

##Category 3.1 Network Configuration - Network Parameters (Host Only)
echo
echo -e "${BLUE}3.1 Network Configuration - Network Parameters (Host Only)${NC}"

# 3.1.1 Ensure IP forwarding is disabled
echo
echo -e "${RED}3.1.1${NC} Ensure IP forwarding is disabled"
egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"
success=$((success + 1))

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

#Ensure broadcast ICMP requests are ignored
echo
echo -e "${RED}3.2.5${NC} Ensure broadcast ICMP requests are ignored"
egrep -q "^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_echo_ignore_broadcasts = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure broadcast ICMP requests are ignored"
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure broadcast ICMP requests are ignored"
    fail=$((fail + 1))
fi

#Ensure bogus ICMP responses are ignored
echo
echo -e "${RED}3.2.6${NC} Ensure bogus ICMP responses are ignored"
egrep -q "^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_ignore_bogus_error_responses = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure bogus ICMP responses are ignored"
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure bogus ICMP responses are ignored"
    fail=$((fail + 1))
fi

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
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure TCP SYN Cookies is enabled"
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure TCP SYN Cookies is enabled"
    fail=$((fail + 1))
fi

##Category 3.5 Network Configuration - Uncommon Network Protocols
echo
echo -e "${BLUE}3.5 Network Configuration - Uncommon Network Protocols${NC}"

# 3.5.3 Ensure RDS is disabled
echo
echo -e "${RED}3.5.3${NC} Ensure RDS is disabled"
modprobe -n -v rds | grep "^install /bin/true$" || echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf
lsmod | egrep "^rds\s" && rmmod rds
echo -e "${GREEN}Remediated:${NC} Ensure RDS is disabled"
success=$((success + 1))

##Category 4.2 Logging and Auditing - Configure rsyslog
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure rsyslog${NC}"

# 4.2.1.1 Ensure rsyslog Service is enabled
echo
echo -e "${RED}4.2.1.1${NC} Ensure rsyslog Service is enabled"
systemctl enable rsyslog
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

##Category 4.2 Logging and Auditing - Configure Logging
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure Logging${NC}"

#Ensure rsyslog or syslog-ng is installed
echo
echo -e "${RED}4.2.3${NC} Ensure rsyslog or syslog-ng is installed"
apt-get install rsyslog || apt-get install syslog-ng
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure rsyslog or syslog-ng is installed"
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog or syslog-ng is installed"
    fail=$((fail + 1))
fi

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

##Category 5.2 Access, Authentication and Authorization - SSH Server Configuration
echo
echo -e "${BLUE}5.2 Access, Authentication and Authorization - SSH Server Configuration${NC}"

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

# 5.2.10 Ensure SSH PermitEmptyPasswords is disabled
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

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"

# 6.1.2 Ensure permissions on /etc/passwd are configured
echo
echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
chown root:root /etc/passwd && chmod 644 /etc/passwd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are configured"
    fail=$((fail + 1))
fi

# 6.1.4 Ensure permissions on /etc/group are configured
echo
echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
chown root:root /etc/group && chmod 644 /etc/group
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
    success=$((success + 1))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are configured"
    fail=$((fail + 1))
fi

###########################################################################################################################

echo
echo -e "${GREEN}Remediation script for Azure Ubuntu 18.04 executed successfully!!${NC}"
echo
echo -e "${YELLOW}Summary:${NC}"
echo -e "${YELLOW}Remediation Passed:${NC} $success" 
echo -e "${YELLOW}Remediation Failed:${NC} $fail"

###########################################################################################################################