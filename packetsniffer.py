import scapy.all as scapy
from scapy.layers import http


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet[http.HTTPRequest].Method == b'POST':
            print(packet[scapy.Raw].load)


sniffer('eth0')
