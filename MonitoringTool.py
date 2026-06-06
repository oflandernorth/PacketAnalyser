import sys
import requests
from scapy.all import *

IPs = {}
safelist = 0

def main():  
    global safelist
    print("Choose the type of operation you want to perform.")
    opType = input("live for live capture / read for capture file reading: ")
    safelist = input("if you want to check against a list of safe ips enter the txt files address: ")
    if safelist != 0:
        safelist = open(safelist)
        safelist = safelist.read()
        safelist = safelist.split("\n")
    match (opType):
        case "live":
            print("starting live capture")
            liveCap()
            pass
        case "read":
            print("state the file to capture from")
            pass
        case _:
            print("please enter a proper operation type \n\n")
            main()
            pass
    ip_checker()
def liveCap():
    #intf = input("which interface to sniff on: ")
    intf = "Wi-Fi"
    endcon = input("when should the capture end, time based or amount based: ")
    match (endcon):
        case "time":
            timeO = int(input("how long to capture for: "))
            sniff(iface=intf, prn= analysis_func, store=False, filter="ip", timeout= timeO)
            pass
        case "amount":
            counT = int(input("how many packets to capture: "))
            sniff(iface=intf, prn= analysis_func, store=False, filter="ip", count= counT)
            pass
        case _:
            print("Choose between time and amount")
            liveCap()
            pass

def analysis_func(pkt):
    if IP in pkt:
        src = pkt["IP"].src
        dst = pkt["IP"].dst
        proto = pkt["IP"].proto
        flags = 0
        sport = 0
        dport = 0
        match (proto):
            case 6:
                sport = pkt["TCP"].sport
                dport = pkt["TCP"].dport
                flags = pkt["TCP"].flags
                pass
            case 17:
                sport = pkt["UDP"].sport
                dport = pkt["UDP"].dport
                pass
            case 1:
                pass
            case _:
                print(f"Unknown protocol packet from {src}")
                pass
        
        #print(f"source = {src}, destination = {dst}, protocol = {proto}, sport = {sport}, dport = {dport}, flags = {flags}")
        packet_to_list(src, dst, proto, sport, dport, flags)

def packet_to_list(src, dst, proto, sport, dport, flags):
    global IPs
    if src in safelist:
        pass
    else:
        if src not in IPs:
            IPs.update({src: {"proto": proto, "dport": dport, "flags": flags, "count" : 0}})
        else:
            count = IPs[src]["count"]+1
            IPs.update({src: {"proto": proto, "dport": dport, "flags": flags, "count" : count}})

def ip_checker():
    # Geo Ip checker to check against dangerous countries
    for ip in IPs:
        response = requests.get(f'https://api.hackertarget.com/geoip/?q={ip}').content.decode().splitlines()[1].split(':', 1)[1].strip()
        print(response)

try:
    if sys.argv[1] == "live":
        liveCap()
    if sys.argv[1] ==  "test":
        ip_checker()
except Exception as e:
    if __name__ == "__main__":
        main()