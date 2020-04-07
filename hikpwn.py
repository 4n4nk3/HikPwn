#!/usr/bin/python3
"""HikPwn, a simple scanner for Hikvision devices with basic vulnerability scanning capabilities written in Python 3.8.\n"""

# Written By Ananke: https://github.com/4n4nk3
# TODO: Add detection and exploitation capabilities for ICSA-17-124-01.
import argparse
from functools import total_ordering
from collections import OrderedDict
from ipaddress import ip_address, IPv4Address
from sys import exit
from time import sleep
from typing import Dict, Any

from lxml import etree
from scapy.all import *


@total_ordering
class HikDevice:
    """Hikvision Device Object to hold the information that we acquire about it.\n"""
    def __init__(self, ip, description=None, serial_number=None, mac=None, ip_mask=None, ip_gateway=None, dhcp=None,
                    software_version=None, dsp_version=None, boot_time=None, activation_status=None,
                    password_reset_ability=None, arp_req_target=None):
        self.ip = ip if isinstance(ip, IPv4Address) else ip_address(ip)
        self.description = description
        self.serial_number = serial_number
        self.mac = mac
        self.ip_mask = ip_mask
        self.ip_gateway = ip_gateway
        self.dhcp = dhcp
        self.software_version = software_version
        self.dsp_version = dsp_version
        self.boot_time = boot_time
        self.activation_status = activation_status
        self.password_reset_ability = password_reset_ability
        self.arp_req_target = arp_req_target

    def __eq__(self, other):
        return self.ip() == other.ip()

    def __lt__(self, other):
        return self.ip() < other.ip()


HIK_KNOWN_HW = {
    'c4:2f:90': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    'c0:56:e3': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    'bc:ad:28': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    'b4:a3:82': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    'a4:14:37': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    '54:c4:15': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    '4c:bd:8f': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    '44:19:b6': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    '28:57:be': 'Hangzhou Hikvision Digital Technology Co.,Ltd.',
    '18:68:cb': 'Hangzhou Hikvision Digital Technology Co.,Ltd.'
}

DETECTED_PASSIVE: Dict[str, HikDevice] = {}
DETECTED_ACTIVE: Dict[str, HikDevice] = {}


def init_argparse() -> argparse.ArgumentParser:
    """Define and manage arguments passed to HikPwn via terminal.\n"""
    # Description
    parser = argparse.ArgumentParser(
        description='HikPwn, a simple scanner for Hikvision devices with basic vulnerability scanning capabilities '
                    'written in Python 3.8. by Ananke: https://github.com/4n4nk3.')
    # Required arguments
    parser.add_argument('--interface', help='the network interface to use', required=True)
    parser.add_argument('--address', help='the ip address of the selected network interface', required=True)
    # Optional arguments
    parser.add_argument('--active', help='enable "active" discovery', required=False, action='store_true')
    return parser


def check_pkt_passive(pkt):
    """Function executed to check if passively sniffed ARP packets come from Hikvision devices.\n"""
    global DETECTED_PASSIVE
    if pkt[ARP].hwsrc[:8] in HIK_KNOWN_HW:
        ip = pkt[ARP].psrc
        if ip not in DETECTED_PASSIVE:
            DETECTED_PASSIVE[ip] = HikDevice(ip=ip, mac=pkt[ARP].hwsrc, arp_req_target=pkt[ARP].pdst)


def check_pkt_active(pkt):
    """Function executed to extract data obtained by actively probing Hikvision devices.\n"""
    global DETECTED_ACTIVE
    try:
        response = pkt[UDP].load
        check_xmlroot = etree.fromstring(response)
        ip = check_xmlroot.find('IPv4Address').text
        description = check_xmlroot.find('DeviceDescription').text
        if ip not in DETECTED_ACTIVE:
            DETECTED_ACTIVE[ip] = HikDevice(ip=ip,
                                            description=description,
                                            serial_number=check_xmlroot.find('DeviceSN').text[len(description):],
                                            mac=check_xmlroot.find('MAC').text.replace('-', ':'),
                                            ip_mask=check_xmlroot.find('IPv4SubnetMask').text,
                                            ip_gateway=check_xmlroot.find('IPv4Gateway').text,
                                            dhcp=check_xmlroot.find('DHCP').text,
                                            software_version=check_xmlroot.find('SoftwareVersion').text,
                                            dsp_version=check_xmlroot.find('DSPVersion').text,
                                            boot_time=check_xmlroot.find('BootTime').text,
                                            activation_status=check_xmlroot.find('Activated').text,
                                            password_reset_ability=check_xmlroot.find('PasswordResetAbility').text
                                            )
    except Exception as exception:
        print(exception)
        print('[!] Error: in check_pkt_active')


def passive_detect():
    """Passively sniff for ARP packets and check if they come from Hikvision devices.\n"""
    if args.active is not True:
        print('[*] Started 30 seconds of passive discovery...\n')
    try:
        sniff(filter='arp', iface=args.interface, prn=check_pkt_passive, store=0, timeout=30)
    except Exception as exception:
        print(exception)
        print('[!] Error: Failed to Initialize Sniffing')
        exit(1)


def active_detect_by_probe():
    """Passively sniff for UDP packets sent by Hikvision devices in response to specific packet probes.\n"""
    wire_filter = 'udp and port 37020 and not host 239.255.255.250'
    try:
        sniff(filter=wire_filter, iface=args.interface, prn=check_pkt_active, store=0, timeout=30)
    except Exception as exception:
        print(exception)
        print('[!] Error: Failed to Initialize Sniffing')
        exit(1)


def send_probe() -> bool:
    """Actively send specific packet probes to all Hikvision devices reachable in LAN.\n"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        sock.bind((args.address, 37020))
        # Uuid is arbitrary and it will be reused by the Hikvision devices inside their responses to our probes.
        probe = '<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>LEET-HAXOR</Uuid><Types>inquiry</Types></Probe>'
        sock.sendto(bytes(probe, 'utf-8'), ('239.255.255.250', 37020))
        return True
    except Exception as exception:
        print(exception)
        print('[!] Error: Failed to send_probe. Active discovery will probably fail.')
        return False


# Parsing arguments
args = init_argparse().parse_args()

print(f'\nUsing {args.interface} as network interface and {args.address} as its IP address...\n')

# Defining and starting a thread for passive detection
THREAD1 = threading.Thread(name='sic1', target=passive_detect)
THREAD1.start()

if args.active is True:
    # Defining and starting a thread for active detection.
    print('[*] Started 30 seconds of both passive and active discovery...')
    THREAD2 = threading.Thread(name='sic2', target=active_detect_by_probe)
    THREAD2.start()
    # While sniffing for probe responses, start sending probe requests every 5 seconds.
    while THREAD2.is_alive():
        sleep(2)
        if not THREAD2.is_alive() or send_probe() is False:
            break
        sleep(3)
    THREAD2.join()

# Wait for THREAD to finish in order not to loose any result by printing them before their capture
THREAD1.join()

# Sorting devices
DETECTED_ACTIVE = OrderedDict(sorted(DETECTED_ACTIVE.items()))
DETECTED_PASSIVE = OrderedDict(sorted(DETECTED_PASSIVE.items()))

# Printing results
print(f'\n{80 * "="}')
if not DETECTED_ACTIVE and not DETECTED_PASSIVE:
    print('[*] Both passive and active discovery didn\'t find any device.')
else:
    if DETECTED_PASSIVE or DETECTED_ACTIVE:
        # Create a sorted list of IPs eliminating duplicates by using a set())
        total = sorted(set().union(
            [DETECTED_ACTIVE[device].ip for device in DETECTED_ACTIVE],
            [DETECTED_PASSIVE[device].ip for device in DETECTED_PASSIVE])
        )
        print(f'[*] Total detected devices: {len(total)}\n')
        for device in total:
            print(f'\t{device}')

    print(f'\n\n{80 * "="}')
    if args.active is True:
        if DETECTED_ACTIVE:
            print('[*] Active discovery\'s results:')
            for number, device in enumerate(DETECTED_ACTIVE):
                print(f'\nDEVICE #{number + 1}:\n\t{"LABEL":<25} {"DATA":<10}\n\t{50 * "-"}')
                for attribute, value in DETECTED_ACTIVE[device].__dict__.items():
                    if value is not None:
                        try:
                            print(f'\t{attribute:<25} {value:<10}')
                        except TypeError as err:
                            if attribute == 'ip':
                                print(f'\t{attribute:<25} {str(value):<10}')
                            else:
                                print('Unexpected exception!')
                                raise
        else:
            print('[*] Active discovery didn\'t find any device.')

    print(f'\n\n{80 * "="}')
    if DETECTED_PASSIVE:
        print('[*] Passive discovery\'s results:')
        for number, device in enumerate(DETECTED_PASSIVE):
            print(f'\nDEVICE #{number + 1}:')
            print(f'\tDetected a device with ip address {DETECTED_PASSIVE[device].ip} and MAC address {DETECTED_PASSIVE[device].mac}.')
    elif args.active is not True or DETECTED_ACTIVE:
        print('[*] Passive discovery didn\'t find any device.')