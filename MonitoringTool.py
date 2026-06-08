import sys
import os
import requests
from scapy.all import *
import sqlite3
import yaml
import json
import ipaddress
import datetime

with open("config.yaml", 'r') as file:
    config = yaml.safe_load(file)

script_dir = os.path.dirname(os.path.abspath(__file__))
safelist = os.path.join(script_dir, config['paths']['safelist'])
countries = os.path.join(script_dir, config['paths']['countries'])
if safelist != '':
    safelist = open(safelist)
    safelist = safelist.read()
    safelist = safelist.split("\n")
else:
    safelist = False
if countries != '':
    countries = open(countries)
    countries = countries.read()
    countries = countries.split("\n")
else:
    countries = False
checkApi = config['data']['abuseipdb']
intf = config['data']['network_interface']
conn = sqlite3.connect(config['paths']['database'])
threshold = config['data']['count_threshold']
suspicious_ports = config['data']['suspicious_ports']
abuse_threshold = config['data']['abuseipdb_threshold']

recent_ips = {}
ip_observation = {}
c = ''

def main():  
    global conn, c
    opType = input("Choose the mode (live/read): ")
    db_structure()
    match (opType):
        case "live":
            print("Starting live capture")
            live_cap()
            pass
        case "read":
            print("State the file to capture from")
            read_cap()
            pass
        case _:
            print("Please enter a proper operation type \n\n")
            return
    conn.close()


def read_cap():
    return
def live_cap():
    endcon = input("Amount based or time based capture: ").lower()
    match (endcon):
        case "time":
            timeO = int(input("How long to capture for: "))
            sniff(iface=intf, prn= analysis_func, store=False, filter="ip", timeout= timeO)
            pass
        case "amount":
            counT = int(input("How many packets to capture: "))
            sniff(iface=intf, prn= analysis_func, store=False, filter="ip", count= counT)
            pass
        case _:
            print("Choose between time and amount")
            live_cap()
            pass

def analysis_func(pkt):
    if IP in pkt:
        src = pkt["IP"].src
        # Check if the source IP is in the safelist
        if safelist and src in safelist:
            print(f"Packet from {src} is in the safelist, skipping analysis.")
            return
        dst = pkt["IP"].dst
        proto = pkt["IP"].proto
        tstamp = datetime.datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
        size = len(pkt.payload)
        flags = 0
        sport = 0
        dport = 0
        if src.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                      '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                      '172.30.', '172.31.', '192.168.')):
            return
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
            case _:
                print(f"Unknown protocol packet from {src}")
                pass
        packet_to_database(1 ,gen_id(src), src, tstamp, 0)
        if src in recent_ips:
            recent_ips[src]["count"] += 1
        else:
            recent_ips.update({src: {"count": 1}})
        pkt_checker(src, dst, proto, sport, dport, flags, size)

def pkt_checker(src, dst, proto, sport, dport, flags, size):
    # Check if the source IP is from a dangerous country
    if countries:
        response = get_country(src)
        if not response:
            pass
        else:
            if response in countries:
                print(f"Packet from {src} is from an unsafe country: {response}")
                packet_to_database(1, gen_id(src), src, risk=5)
                packet_to_database(2, gen_id(src), src, flag_reason=f"From {response}", source="GeoIP")
    # Check against abuseipdb database for reports of malicious activity
    if checkApi != '' and src not in recent_ips:
        querystring = {
            'ipAddress': src,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': checkApi,
        }
        response = requests.request(method='GET', url='https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring)
        response = json.loads(response.text)
        if response["data"]["totalReports"] > abuse_threshold:
            print(f"Packet from {src} has been reported {response['data']['totalReports']} times in the last 90 days")
            packet_to_database(1, gen_id(src), src, risk=10)
            packet_to_database(2, gen_id(src), src, flag_reason=f"{response['data']['totalReports']} reports", source="AbuseIPDB")
    # Check for repeated packets from the same IP
    if recent_ips[src]["count"] > threshold:
        print(f"Packet from {src} has been observed {recent_ips[src]['count']} times")
        packet_to_database(1, gen_id(src), src, risk=5)
        packet_to_database(2, gen_id(src), src, flag_reason=f"{recent_ips[src]['count']} packets observed", source="Internal Scans")
    # Check for common attack ports
    if dport in suspicious_ports:
        print(f"Packet from {src} is targeting a common attack port: {dport}")
        packet_to_database(1, gen_id(src), src, risk=20)
        packet_to_database(2, gen_id(src), src, flag_reason=f"Targeting port {dport}", source="Port Scanning")
    # Store raw packet summary in the database
    packet_to_database(3, gen_id(src), src, proto=proto, sport=sport, dport=dport, size=size)
# -------------- HELPER FUNCTIONS --------------
def get_country(ip):
    # Check the cache first (avoid hitting the API for the same IP)
    if ip in recent_ips and "country" in recent_ips[ip]:
        return False
    # If not in cache, make the API call to ip-api.com
    try:
        url = f'http://ip-api.com/json/{ip}'
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        data = response.json()
        if data.get('status') == 'success':
            country = data.get('country', 'Unknown')
        else:
            print(f"ip-api lookup failed for {ip}: {data.get('message', 'Unknown error')}")
            country = 'Unknown'

        recent_ips[ip]["country"] = country
        return country

    except Exception as e:
        print(f"Error during ip-api lookup for {ip}: {e}")
        return 'Unknown'
def gen_id(src):
    # Generate a unique ID based on the source IP
    return int(ipaddress.IPv4Address(src))
def read_id(id):
    # Convert the unique ID back to an IP address
    return str(ipaddress.IPv4Address(id))
def db_structure():
    global conn, c
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ip_observations (
                ID INTEGER PRIMARY KEY,
                IP TEXT ,
                FSEEN TEXT,
                LSEEN TEXT,
                RISK INTEGER
            )''')
    c.execute('''CREATE TABLE IF NOT EXISTS suspicious_flags (
               ID INTEGER PRIMARY KEY AUTOINCREMENT,
               OBSERVATION_ID INTEGER,
               FLAG_REASON TEXT,
               SOURCE TEXT,
               FOREIGN KEY (OBSERVATION_ID) REFERENCES ip_observations(ID) ON DELETE CASCADE
            )''')
    c.execute('''CREATE TABLE IF NOT EXISTS raw_packet_summary (
               ID INTEGER PRIMARY KEY AUTOINCREMENT,
               OBSERVATION_ID INTEGER,
               PROTOCOL TEXT,
               SRC_PORT INTEGER,
               DST_PORT INTEGER,
               PACKET_SIZE INTEGER,
               FOREIGN KEY (OBSERVATION_ID) REFERENCES ip_observations(ID) ON DELETE CASCADE
            )''')
    conn.commit()
def packet_to_database(type, id,src, time=None, risk=0, proto=None, sport=None, dport=None, flags=None, size=None, flag_reason=None, source=None):
    match (type):
        case 1:
            c.execute('''
                INSERT INTO ip_observations (ID, IP, FSEEN, LSEEN, RISK)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ID) DO UPDATE SET LSEEN=excluded.LSEEN, RISK= RISK + excluded.RISK
            ''', (id, src, time, time, risk))
            conn.commit()
            pass
        case 2:
            c.execute('''
                INSERT INTO suspicious_flags (OBSERVATION_ID, FLAG_REASON, SOURCE)
                VALUES (?, ?, ?)
            ''', (id, flag_reason, source))
            conn.commit()
            pass
        case 3:
            c.execute('''
                INSERT INTO raw_packet_summary (OBSERVATION_ID, PROTOCOL, SRC_PORT, DST_PORT, PACKET_SIZE)
                VALUES (?, ?, ?, ?, ?)
            ''', (id, proto, sport, dport, size))
            conn.commit()
            pass
        case _:
            pass

if __name__ == "__main__":
    main()
