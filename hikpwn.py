#!/usr/bin/python3
"""HikPwn, a simple scanner for Hikvision devices with basic vulnerability scanning capabilities written in Python 3.8.\n"""

# Written By Ananke: https://github.com/4n4nk3
# TODO: Add detection and exploitation capabilities for ICSA-17-124-01.
import argparse
from sys import exit
from time import sleep

from lxml import etree
from scapy.all import *

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

DETECTED_PASSIVE = set()
DETECTED_ACTIVE = defaultdict(dict)


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
        DETECTED_PASSIVE.add(
            'Request: {} with HWD-ID {} is asking about {}'.format(pkt[ARP].psrc, pkt[ARP].hwsrc, pkt[ARP].pdst))


def check_pkt_active(pkt):
    """Function executed to extract data obtained by actively probing Hikvision devices.\n"""
    global DETECTED_ACTIVE
    try:
        response = pkt[UDP].load
        xmlroot = etree.fromstring(response)
        device_description = xmlroot.find('DeviceDescription').text
        device_serial_number = xmlroot.find('DeviceSN').text[len(device_description):]
        if device_serial_number not in DETECTED_ACTIVE:
            DETECTED_ACTIVE[device_serial_number]['Serial Number'] = device_serial_number
            DETECTED_ACTIVE[device_serial_number]['Description'] = device_description
            DETECTED_ACTIVE[device_serial_number]['MAC'] = xmlroot.find('MAC').text
            DETECTED_ACTIVE[device_serial_number]['IP'] = xmlroot.find('IPv4Address').text
            DETECTED_ACTIVE[device_serial_number]['DHCP in use'] = xmlroot.find('DHCP').text
            DETECTED_ACTIVE[device_serial_number]['Software Version'] = xmlroot.find('SoftwareVersion').text
            DETECTED_ACTIVE[device_serial_number]['DSP Version'] = xmlroot.find('DSPVersion').text
            DETECTED_ACTIVE[device_serial_number]['Boot Time'] = xmlroot.find('BootTime').text
            DETECTED_ACTIVE[device_serial_number]['Activation Status'] = xmlroot.find('Activated').text
            DETECTED_ACTIVE[device_serial_number]['Password Reset Ability'] = xmlroot.find('PasswordResetAbility').text
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
    wire_filter = 'udp and port 37020 and host ' + args.address + ' and not host 239.255.255.250'
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

# Printing results
if args.active is True:
    if not DETECTED_ACTIVE and not DETECTED_PASSIVE:
        print('\n\n[*] Both passive and active discovery didn\'t find any device.')
    elif DETECTED_ACTIVE:
        print('\n\n[*] Active discovery\'s results:')
        for number, device in enumerate(DETECTED_ACTIVE):
            print(f'\nDEVICE #{number + 1}:\n\t{"LABEL":<25} {"DATA":<10}\n\t{50 * "-"}')
            # List comprehension to print results in a table like format
            [print(f'\t{label:<25} {DETECTED_ACTIVE[device][label]:<10}') for label in DETECTED_ACTIVE[device]]
    else:
        print('\n\n[*] Active discovery didn\'t find any device.')

if DETECTED_PASSIVE:
    print('\n\n[*] Passive discovery\'s results:\n')
    print(*DETECTED_PASSIVE, sep='\n')  # Object expansion
elif args.active is not True or DETECTED_ACTIVE:
    print('\n\n[*] Passive discovery didn\'t find any device.')
