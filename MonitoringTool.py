import sys
import requests
from scapy.all import *
import sqlite3
import json

IPs = {}
ip_observation = {}
safelist = '.\safelist.txt'
countries = '.\countries.txt'
checkApi = ''
conn = ''
c = ''

def main():  
    global safelist, countries, checkApi, conn, c
    print("Choose the type of operation you want to perform.")
    opType = input("live for live capture / read for capture file reading: ")
    #safelist = input("if you want to check against a list of safe ips enter the txt files address: ")
    if safelist != 0:
        safelist = open(safelist)
        safelist = safelist.read()
        safelist = safelist.split("\n")
    #countries = input("if you want to check against a list of unsafe countries enter the txt files address: ")
    if countries != 0:
        countries = open(countries)
        countries = countries.read()
        countries = countries.split("\n")
    checkApi = input("if you want to check IPs against AbuseIPDB, enter the API key: ").strip()
    conn = sqlite3.connect('PacketAnalyzer.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ip_observations (
                IP TEXT, Dport INTEGER, Protocol INTEGER, Country TEXT, Risk INTEGER)''')
    conn.commit()
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
    c.execute("SELECT * FROM ip_observations")
    for row in c.fetchall():
        print(row)
    conn.close()
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
    global ip_observation, c
    for ip in IPs:
        response = requests.get(f'https://api.hackertarget.com/geoip/?q={ip}').content.decode().split("\n")[1].split(':', 1)[1].strip()
        ip_observation.update({ip: {"dport": IPs[ip]["dport"],  "proto": IPs[ip]["proto"], "country": response, "score": 0}})
        # Check if the IP is from a dangerous country
        if response in countries:
            print(f"Packet from {ip} is from an unsafe country: {response}")
            ip_observation[ip]["score"] += 5
        else:
            ip_observation[ip]["score"] += 0
        # Check against abuseipdb database for reports of malicious activity
        if checkApi != '':
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            headers = {
                'Accept': 'application/json',
                'Key': checkApi,
            }
            response = requests.request(method='GET', url='https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring)
            response = json.loads(response.text)
            if response["data"]["totalReports"] > 5:
                print(f"Packet from {ip} has been reported {response['data']['totalReports']} times in the last 90 days")
                ip_observation[ip]["score"] += 10
        # Check for repeated packets from the same IP
        if IPs[ip]["count"] > 10:
            print(f"Packet from {ip} has been observed {IPs[ip]['count']} times")
            ip_observation[ip]["score"] += 15
        # Check for common attack ports
        if IPs[ip]["dport"] in [22, 23, 445,3389]:
            print(f"Packet from {ip} is targeting a common attack port: {IPs[ip]['dport']}")
            ip_observation[ip]["score"] += 20
        for ip, data in ip_observation.items():
            c.execute('''
                INSERT INTO ip_observations (IP, Dport, Protocol, Country, Risk)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(IP) DO UPDATE SET Risk = Risk + 1
            ''', (ip, data["dport"], data["proto"], data["country"], data["score"]))
        conn.commit()
try:
    if sys.argv[1] == "live":
        liveCap()
    elif sys.argv[1] ==  "test":
        ip_checker()
except Exception as e:
    if __name__ == "__main__":
        main()
