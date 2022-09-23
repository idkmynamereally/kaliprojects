#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    ip_and_mac_list = list()
    for element in answered_list:
        target_client = dict()
        my_answered_packet = element[1]
        target_client['mac'] = my_answered_packet.hwsrc
        target_client['ip'] = my_answered_packet.psrc
        ip_and_mac_list.append(target_client)
    return ip_and_mac_list


def print_ip_and_mac(ip_mac_list):
    print(" IP\t\t MAC Address\n ----------------------------------")
    for client in ip_mac_list:
        print(' ' + client['ip'] + '\t', end=' ')
        print(client['mac'])


print("\t\t--------------Welcome To Slash's Network Scanner---S-----------\n")
print_ip_and_mac(scan('172.192.52.1/24'))
