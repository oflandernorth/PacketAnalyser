import sys
from scapy.all import *

def main():  
    print("Choose the type of operation you want to perform.")
    OpType = input("live for live capture / read for capture file reading: ")
    match (OpType):
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
def liveCap():
    #intf = input("which interface to sniff on: ")
    intf = "Wi-Fi"
    endcon = input("when should the capture end, time based or amount based: ")
    match (endcon):
        case "time":
            timeO = int(input("how long to capture for: "))
            sniff(iface=intf, prn= analysis_func, store=False, filter="ip", timeout= timeO)
        case "amount":
            counT = int(input("how many packets to capture: "))
            sniff(iface=intf, prn= analysis_func, store=False, filter="ip", count= counT)
        case _:
            print("Choose between time and amount")
            liveCap()
            pass
def analysis_func(pkt):
    if pkt:
        print(pkt["IP"])
if sys.argv[1] == "live":
    liveCap()
elif __name__ == "__main__":
    main()