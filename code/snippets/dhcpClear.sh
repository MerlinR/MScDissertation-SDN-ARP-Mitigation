#!/bin/sh
# Remove leases
rm /tmp/dhcp.leases
# Delete ARP table (OpenWRT method)
rm /proc/net/arp
# Clear IP neigh ARP table
ip neigh delete 192.168.4.* dev br-ovs
#Restart DHCP server
/etc/init.d/dnsmasq restart
