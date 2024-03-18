from ipaddress import IPv6Address, IPv4Address

def mac_to_v4(mac):
    mac_value = int(mac.translate({ord(' '): None, ord('.'): None, ord(':'): None, ord('-'): None}), 16)

    #port = mac_value >> 32 & 0xff
    high1 = mac_value >> 24 & 0xff
    high2 = mac_value >> 16 & 0xff
    low1 = mac_value >> 8 & 0xff
    low2 = mac_value & 0xff

    return '{}.{}.{}.{}'.format(high1, high2, low1, low2)

def mac_to_ipv6_linklocal(mac):
    # Remove the most common delimiters; dots, dashes, etc.
    mac_value = int(mac.translate({ord(' '): None, ord('.'): None, ord(':'): None, ord('-'): None}), 16)

    # Split out the bytes that slot into the IPv6 address
    # XOR the most significant byte with 0x02, inverting the 
    # Universal / Local bit
    high2 = mac_value >> 32 & 0xffff ^ 0x0200
    high1 = mac_value >> 24 & 0xff
    low1 = mac_value >> 16 & 0xff
    low2 = mac_value & 0xffff

    return 'fe80::{:04x}:{:02x}ff:fe{:02x}:{:04x}'.format(
        high2, high1, low1, low2)

def converttov6(ipv4address):
    return IPv6Address('2002::' + ipv4address).compressed

def ipv6_to_id(ip, hps):
    ip_int = int(IPv6Address(ip))
    return (ip_int & 0xff) + ((ip_int >> 8 & 0xff) - 1) * hps


def ipv6_to_v4(ip):
    return str(IPv4Address(int(IPv6Address(ip)) & 0xffffffff))

ipv6_to_v4("2002::a00:101")


#print(ipv6_to_id("2002::a00:101"))