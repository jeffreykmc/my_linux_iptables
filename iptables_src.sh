
#!/bin/bash
#
# ========================================================
# Thank you for using this iptables script
# ========================================================
# Notice:
# If anyone download this file from my svn, because I type
# it under M$ environment, it will not interpret as normal
# bash script. Just
# $vi rc.firewall
# In command mod
# :set ff=unix
# :wq
#
#
# History
# 050311 Jeffrey Created
# 050528 Jeffrey Chain - ssh added
# 050702 Jeffrey Chain - squid added
# 050806 Jeffrey IPv6 Block chain added
# 050819 Jeffrey Config added to easy switch on different module
# 060226 Jeffrey Try to Block all port for output and forward
# 060930 Jeffrey Remove All IPv6 Block chain


#-----------------------------------------------------
# GENERAL SECTION
#-----------------------------------------------------

EXT_IF=ppp0
INT_IF=eth1
INNET=192.168.10.0/24

#-----------------------------------------------------
# PORT FORWARD SECTION
#-----------------------------------------------------
# Allow connection from EXT_IF to INT_IF thru certain port
#
# TVAnt: 16800 16900
# VNC: 5800 5900
# VNC Viewer Listen Mode: 5400 5500
# PPLive: 1601 8255 10715
# BitComet: 20465 16800:16900
# Torpark: 9050 9051 9030 9001
#-----------------------------------------------------

PORT_FW_ACTIVE=1
FW_IP=192.168.10.2
ALLOW_PORT_FW="16800 16900 20465 9050 9051 9030 9001"

#-----------------------------------------------------
# CONNECTION FROM INSIDE OUT SECTION
#-----------------------------------------------------
# Allow connection from INT_IF to EXT_IF to certain port
# adn
# Allow connection from server to EXT_IF to certain port
#
# 1 = Allow INT_IF to EXT_IF at certain port
# 0 = Not allow at all (need to change policy)
#
# Port Allow For Following Application
# Google Talk 443 5222
# Skype 80 443
# Y! Group 3478
# NNTP 119
# Diablo2: 4000 6112
#
# Stdtime.gov.hk:
# TVants 16600:16900
# btdownloadheadless: 6881:6883
# torpark: 9001 9030
#-----------------------------------------------------

PORT_FORWARD_ACTIVE=1
PORT_OUTPUT_ACTIVE=1
ALLOW_PORT_FROM_INNET_FW="20 21 22 25 53 80 110 119 123 443 995 3478 5222 6112 4000 8080 8255 10715 16600:16900 9030 9001"
ALLOW_PORT_FROM_INNET_OUT="80 20 21 22 25 110 123 53 995 8245 8080"
#ALLOW_ICMP="0 3 3/4 4 8 11 12 14 16 18"
ALLOW_ICMP=""

#-----------------------------------------------------
# TRANSPARENT PROXY SECTION
#-----------------------------------------------------
#
# 1 = Start up Transparent Proxy
#-----------------------------------------------------

TRAN_PROXY_ACTIVE=1

#-----------------------------------------------------
# VPN SERVER SECTION
#-----------------------------------------------------
# 1 = Start up VPN
#-----------------------------------------------------

VPN_FIREWALL_ACTIVE=0 # Using VPN Server

#-----------------------------------------------------
# SERVER SECTION
#-----------------------------------------------------
# Open port for outsiders
# BT: 6881:6883
# OpenVPN: 1194
#-----------------------------------------------------

ACCEPT_PORT="80 20 21 22 25 1194 6881:6883"

#-----------------------------------------------------
# SQUID SERVICE SECTION
#-----------------------------------------------------
# 1 = Accept Certain Clients
#-----------------------------------------------------

SQUID_ALLOW_ACTIVE=1
ALLOW_SQUID_HOST=""
ALLOW_SQUID_IP=""

#-----------------------------------------------------
# SSHD SERVER SECTION
#-----------------------------------------------------
# 1 = Accept Certain Clients
#-----------------------------------------------------

SSHD_ALLOW_ACTIVE=0
ALLOW_SSHD_HOST=""

#-----------------------------------------------------
# DON'T CHANGE ANYTHING NOW
#-----------------------------------------------------

IPT=/sbin/iptables

declare -i openport
declare -i i

/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe ip_conntrack_ftp
/sbin/modprobe ip_conntrack_irc

EXT_IP=$(ifconfig | grep "$EXT_IF " -A 1 | awk '/inet/ {print $2}' | sed -e 's/.*://')

echo "Current IP is $EXT_IP"
echo "Turning on IP forwarding...."
echo "1" > /proc/sys/net/ipv4/ip_forward
echo "Cleaning up...."
$IPT -F -t filter
$IPT -X -t filter
$IPT -Z -t filter
$IPT -F -t nat
$IPT -X -t nat
$IPT -Z -t nat


$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD DROP
$IPT -P INPUT DROP

$IPT -t nat -P PREROUTING ACCEPT
$IPT -t nat -P POSTROUTING ACCEPT
$IPT -t nat -P OUTPUT ACCEPT

# Allow Local and INTIF
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Trust Internal Network
$IPT -A INPUT -i $INT_IF -j ACCEPT
$IPT -A OUTPUT -o $INT_IF -j ACCEPT

if [ $TRAN_PROXY_ACTIVE == "1" ]; then
echo "Starting Transparent Proxy..."
$IPT -t nat -A PREROUTING -i $INT_IF -p TCP -s $INNET --dport 80 -j REDIRECT --to-ports 3128
fi

if [ $VPN_FIREWALL_ACTIVE == "1" ]; then
echo "Starting VPN Firewall"
$IPT -N vpn
$IPT -A INPUT -i tun0 -j vpn
$IPT -A FORWARD -i tun0 -j vpn
$IPT -A INPUT -i tap0 -j vpn
$IPT -A FORWARD -i tap0 -j vpn
$IPT -A INPUT -i $EXT_IF -p tcp --dport 4710 -j vpn
$IPT -A INPUT -i $EXT_IF -p udp --dport 4710 -j vpn
$IPT -A OUTPUT -o $EXT_IF -p tcp --dport 4710 -j vpn
$IPT -A OUTPUT -o $EXT_IF -p udp --dport 4710 -j vpn
$IPT -A INPUT -i tun0 -j vpn
$IPT -A FORWARD -i tun0 -o $INT_IF -j vpn # assuming eth0 is internal interface
$IPT -A FORWARD -i $INT_IF -o tun0 -j vpn
$IPT -A OUTPUT -o tun0 -j vpn
$IPT -A vpn -j ACCEPT
# change 192.168.0.0/24 to 192.168.1.0/24 for server in network B or
# comment it to prevent any connection from network B to network A using
# NAT
$IPT -t nat -A POSTROUTING -o tun0 -s $INNET -j MASQUERADE
fi

# Prevent Syn Flood Attack
echo "Prevent Syn Flood Attack...."
$IPT -N synflood
$IPT -A synflood -p tcp --syn -m limit --limit 1/s -j RETURN
$IPT -A synflood -p tcp -j REJECT --reject-with tcp-reset
$IPT -A INPUT -p tcp -m state --state NEW -j synflood

#Protect portmap
echo "Protect portmap"
$IPT -A INPUT -p tcp -s! $INNET --dport 111 -j DROP
$IPT -A INPUT -p udp -s! $INNET --dport 111 -j DROP
$IPT -A INPUT -p tcp -s 127.0.0.1 --dport 111 -j ACCEPT

for CUR_PORT in $ALLOW_ICMP
do
echo "$CUR_PORT"
$IPT -A INPUT -i $EXTIF -p icmp --icmp-type $CUR_PORT -j ACCEPT
done

if [ $PORT_FORWARD_ACTIVE == "1" ]; then
echo "Allow INNET connect to INTERNET "
for CUR_PORT in $ALLOW_PORT_FROM_INNET_FW
do
echo "thru port $CUR_PORT"
$IPT -A FORWARD -i $INT_IF -o $EXT_IF -p tcp --dport $CUR_PORT -m state --state NEW -j ACCEPT
$IPT -A FORWARD -i $INT_IF -o $EXT_IF -p udp --dport $CUR_PORT -m state --state NEW -j ACCEPT
done
fi
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

if [ $PORT_OUTPUT_ACTIVE == "1" ]; then
echo "Allow SERVER connect to INTERNET"
$IPT -N chain_port_output_active
for CUR_PORT in $ALLOW_PORT_FROM_INNET_OUT
do
echo "thru port $CUR_PORT"
$IPT -A OUTPUT -o $EXT_IF -p tcp --dport $CUR_PORT -m state --state NEW -j chain_port_output_active
$IPT -A OUTPUT -o $EXT_IF -p udp --dport $CUR_PORT -m state --state NEW -j chain_port_output_active
done
fi
$IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j chain_port_output_active
$IPT -A chain_port_output_active -j ACCEPT

#Port Forward Script
if [ $PORT_FW_ACTIVE == "1" ]; then
echo "Allow Connection from INTERNET to INNET ($FW_IP)"
for CUR_PORT in $ALLOW_PORT_FW
do
echo "thru Port $CUR_PORT to $FW_IP"
$IPT -t nat -A PREROUTING -p tcp -i $EXT_IF --dport $CUR_PORT -j DNAT --to $FW_IP:$CUR_PORT
$IPT -t nat -A PREROUTING -p udp -i $EXT_IF --dport $CUR_PORT -j DNAT
