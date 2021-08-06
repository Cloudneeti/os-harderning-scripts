#!/bin/bash

: '
#SYNOPSIS
    Quick win script for remediation of Ubuntu baseline misconfigurations.
.DESCRIPTION
    This script will remediation all possible OS baseline misconfigurations for Ubuntu 18.04 based Virtual machines.

.NOTES

    Copyright (c) Cloudneeti. All rights reserved.
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

############################################################################################################################

##Category Azure (ASC) Services - Special Purpose Services
echo
echo -e "${BLUE}Azure (ASC) Services - Special Purpose Services${NC}"

#CCE-14068-1 : The postfix package should be uninstalled.
echo
echo -e "${RED}CCE-14068-1${NC} The postfix package should be uninstalled"
apt-get remove postfix
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The postfix package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The postfix package should be uninstalled"
  fail=$((fail + 1))
fi

#CCE-14495-6 : The sendmail package should be uninstalled.
echo
echo -e "${RED}CCE-14495-6${NC} The sendmail package should be uninstalled"
apt-get remove sendmail
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The sendmail package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The sendmail package should be uninstalled"
  fail=$((fail + 1))
fi

#The rpcidmapd service should be disabled
echo
echo -e "${RED}CCE-3568-3${NC} The rpcidmapd service should be disabled"
chkconfig rpcidmapd off
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The rpcidmapd service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The rpcidmapd service should be disabled"
  fail=$((fail + 1))
fi

#CCE-4464-4 : The isc-dhcp-server package should be uninstalled
echo
echo -e "${RED}CCE-4464-4${NC} The isc-dhcp-server package should be uninstalled"
apt-get remove isc-dhcp-server
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The isc-dhcp-server package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The isc-dhcp-server package should be uninstalled"
  fail=$((fail + 1))
fi

#CCE-3705-1 : The ypbind service should be disabled.
echo
echo -e "${RED}CCE-3705-1${NC} The ypbind service should be disabled"
systemctl disable ypbind
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The ypbind service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The ypbind service should be disabled"
  fail=$((fail + 1))
fi

#CCE-4491-7 : The rpcsvcgssd service should be disabled
echo
echo -e "${RED}CCE-4491-7${NC} The rpcsvcgssd service should be disabled"
systemctl disable rpcsvcgssd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The rpcsvcgssd service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The rpcsvcgssd service should be disabled"
  fail=$((fail + 1))
fi

#CCE-4308-3 : The rsh-server package should be uninstalled
echo
echo -e "${RED}CCE-4308-3${NC} The rsh-server package should be uninstalled"
apt-get remove rsh-server
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The rsh-server package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The rsh-server package should be uninstalled"
  fail=$((fail + 1))
fi

#The readahead-fedora package should be uninstalled
echo
echo -e "${RED}CCE-4421-4${NC} The readahead-fedora package should be uninstalled"
apt-get remove readahead-fedora
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The readahead-fedora package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The readahead-fedora package should be uninstalled"
  fail=$((fail + 1))
fi

#The dovecot package should be uninstalled
echo
echo -e "${RED}CCE-4239-0${NC} The dovecot package should be uninstalled"
apt-get remove dovecot
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The dovecot package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The dovecot package should be uninstalled"
  fail=$((fail + 1))
fi

#The tftpd package should be uninstalled
echo
echo -e "${RED}CCE-3916-4${NC} The tftpd package should be uninstalled"
apt-get remove tftpd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The tftpd package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The tftpd package should be uninstalled"
  fail=$((fail + 1))
fi

#The portmap service should be disabled
echo
echo -e "${RED}CCE-4550-0${NC} The portmap service should be disabled"
service portmap stop
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The portmap service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The portmap service should be disabled"
  fail=$((fail + 1))
fi

#The rpcgssd service should be disabled
echo
echo -e "${RED}CCE-3535-2${NC} The rpcgssd service should be disabled"
service rpcgssd stop
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The rpcgssd service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The rpcgssd service should be disabled"
  fail=$((fail + 1))
fi

#The kdump service should be disabled
echo
echo -e "${RED}CCE-3425-6${NC} The kdump service should be disabled"
apt-get remove kdump-tools
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The kdump service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The kdump service should be disabled"
  fail=$((fail + 1))
fi

#The isdnutils-base package should be uninstalled
echo
echo -e "${RED}CCE-14825-4${NC} The isdnutils-base package should be uninstalled"
apt-get remove isdnutils-base
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The isdnutils-base package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The isdnutils-base package should be uninstalled"
  fail=$((fail + 1))
fi

#The isdn service should be disabled
echo
echo -e "${RED}CCE-4286-1${NC} The isdn service should be disabled"
service isdn stop
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The isdn service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The isdn service should be disabled"
  fail=$((fail + 1))
fi

#The bind package should be uninstalled
echo
echo -e "${RED}CCE-4219-2${NC} The bind package should be uninstalled"
apt-get remove bind9
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The bind package should be uninstalled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The bind package should be uninstalled"
  fail=$((fail + 1))
fi

#Ensure auditd package is installed
echo
echo -e "${RED}CCE-4240-1${NC} Ensure auditd package is installed"
apt-get install -y auditd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure auditd package is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure auditd package is installed"
  fail=$((fail + 1))
fi

#The bluetooth/hidd service should be disabled
echo
echo -e "${RED}CCE-4355-4${NC} The bluetooth/hidd service should be disabled"
systemctl disable bluetooth.service
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} The bluetooth/hidd service should be disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} The bluetooth/hidd service should be disabled"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category Azure (ASC) Network Configuration - Network Parameters (Host Only)
echo
echo -e "${BLUE}Azure (ASC)  Network Configuration - Network Parameters (Host Only)${NC}"

#CCE-4236-6 : Accepting source routed packets should be disabled for all interfaces. (net.ipv6.conf.all.accept_source_route = 0)
echo
echo -e "${RED}CCE-4236-6${NC} Accepting source routed packets should be disabled for all interfaces. (net.ipv6.conf.all.accept_source_route = 0)"
egrep -q "^(\s*)net.ipv6.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv6.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Accepting source routed packets should be disabled for all interfaces. (net.ipv6.conf.all.accept_source_route = 0)"
success=$((success + 1))

###########################################################################################################################

##Category Azure (ASC) System Maintenance - System File Permissions
echo
echo -e "${BLUE}Azure (ASC) System Maintenance - System File Permissions${NC}"

#File permissions for /etc/anacrontab should be set to root:root 600
echo
echo -e "${RED}CCE-4304-2${NC} File permissions for /etc/anacrontab should be set to root:root 600"
chown root:root /etc/anacrontab && chmod 600 /etc/anacrontab
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} File permissions for /etc/anacrontab should be set to root:root 600"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} File permissions for /etc/anacrontab should be set to root:root 600"
  fail=$((fail + 1))
fi

###########################################################################################################################

##Category Initial Setup - Additional Process Hardening
echo
echo -e "${BLUE}1.5 Initial Setup - Additional Process Hardening${NC}"

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

###########################################################################################################################

##Category 2.1 Services - inetd Services
echo
echo -e "${BLUE}2.1 Services - inetd Services${NC}"

# 2.1.6 Ensure rsh server is not enabled / The rlogin service should be disabled
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
success=$((success + 2))

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

# 2.2.3 Ensure Avahi Server is not enabled / Zeroconf networking should be disabled
echo
echo -e "${RED}2.2.3${NC} Ensure Avahi Server is not enabled"
systemctl disable avahi-daemon
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure Avahi Server is not enabled"
    success=$((success + 2))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure Avahi Server is not enabled"
    fail=$((fail + 2))
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

# 2.2.8 Ensure DNS Server is not enabled / The named service should be disabled
echo
echo -e "${RED}2.2.8${NC} Ensure DNS Server is not enabled"
systemctl disable bind9
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure DNS Server is not enabled"
    success=$((success + 2))
else
    echo -e "${RED}UnableToRemediate:${NC} Ensure DNS Server is not enabled"
    fail=$((fail + 2))
fi

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
apt-get remove telnet
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
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"
success=$((success + 1))

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

###########################################################################################################################

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

###########################################################################################################################

##Category 4.1 Logging and Auditing - Configure System Accounting (auditd)
echo
echo -e "${BLUE}4.1 Logging and Auditing - Configure System Accounting (auditd)${NC}"

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

###########################################################################################################################

##Category 4.2 Logging and Auditing - Configure Logging
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure Logging${NC}"

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

###########################################################################################################################

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

###########################################################################################################################

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

###########################################################################################################################

#5.2.3 Ensure SSH LogLevel is set to INFO
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

############################################################################################################################

##Category 5.3 Access, Authentication and Authorization - Configure PAM
echo
echo -e "${BLUE}5.3 Access, Authentication and Authorization - Configure PAM${NC}"

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

# 5.4.1.2 Ensure minimum days between password changes is 7 or more
echo
echo -e "${RED}5.4.1.2${NC} Ensure minimum days between password changes is 7 or more"
egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 7\2/" /etc/login.defs || echo "PASS_MIN_DAYS 7" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --mindays 7
echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is 7 or more"
success=$((success + 1))

###########################################################################################################################

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