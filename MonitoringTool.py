import sys
import os
import requests
from scapy.all import *
import sqlite3
import yaml
import json
import csv
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
abuseipdb_key = config['data']['abuseipdb']
intf = config['data']['network_interface']
conn = sqlite3.connect(config['paths']['database'])
conn.execute("PRAGMA foreign_keys = ON;")
c = conn.cursor()
threshold = config['data']['count_threshold']
suspicious_ports = config['data']['suspicious_ports']
abuse_threshold = config['data']['abuseipdb_threshold']
risk_weights = config['risk_weights']
IPThreat_state = config['data']['ipthreat']

recent_ips = {}

def main():  
    global conn, c
    opType = input("Choose the mode (live/read/database): ")
    db_structure()
    match (opType):
        case "live":
            print("Starting live capture")
            if IPThreat_state:
                download_ipthreat()
            live_cap()
            pass
        case "read":
            print("State the file to capture from")
            if IPThreat_state:
                download_ipthreat()
            read_cap()
            pass
        case "database":
            pass
        case _:
            print("Please enter a proper operation mode \n\n")
            return
    print('''
          Choose the next step:
            1. View top 10 suspicious IPs
            2. View top 10 suspicious IPs with flags
            3. Delete database and start over
            4. Delete one IP from database
            5. View all observations for one IP
            6. Exit
          ''')
    nextStep = input("Enter the option number: ")
    match (nextStep):
        case "1":
            found = False
            rows = []
            for row in c.execute('SELECT IP, RISK FROM ip_observations ORDER BY RISK DESC LIMIT 10'):
                found = True
                rows.append(row)
                print(f"IP: {row[0]}, Risk Score: {row[1]}")
            if not found:
                print("No data in database")
            else:
                csv_export(rows, 'Top10Sum')    
            pass
        case "2":
            found = False
            rows = []
            for row in c.execute('''
                SELECT ip_observations.IP, ip_observations.RISK, GROUP_CONCAT(suspicious_flags.FLAG_REASON || ' (Source: ' || suspicious_flags.SOURCE || ')', '; ')
                FROM ip_observations
                LEFT JOIN suspicious_flags ON ip_observations.ID = suspicious_flags.OBSERVATION_ID
                WHERE ip_observations.RISK > 0
                GROUP BY ip_observations.ID
                ORDER BY ip_observations.RISK DESC
                LIMIT 10
            '''):
                found = True
                rows.append(row)
                print(f"IP: {row[0]}, Risk Score: {row[1]}, Flags: {row[2]}")
            if not found:
                print("No data in database")
            else:
                csv_export(rows, 'Top10SumFlag')    
            pass
        case "3":
            confirm = input("Are you sure you want to delete the data in database? (yes/no): ").lower()
            if confirm == "yes":
                c.execute('DELETE FROM ip_observations')
                c.execute('DELETE FROM suspicious_flags')
                c.execute('DELETE FROM raw_packet_summary')
                conn.commit()
                print("Database cleared.")
            else:
                print("Operation cancelled.")
            pass
        case "4":
            ip = input("Enter the IP address to delete: ").strip()
            c.execute('DELETE FROM ip_observations WHERE ID = ?', (gen_id(ip),))
            conn.commit()
        case "5":
            ip = input("Enter the IP address to view observations for: ").strip()
            for row in c.execute('SELECT * FROM ip_observations WHERE IP = ?', (ip,)):
                print(f"Observation: {row}")
        case "6":
            print("Exiting...")
            pass
        case _:
            print("Please enter a proper option number")
    conn.close()

def read_cap():
    file = input("Pcap file location: ")
    with PcapReader(file) as pcap_reader:
        for pkt in pcap_reader:
            analysis_func(pkt)

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
            recent_ips.update({src: {"count": 1, "AbuseIPDB": False, "IPThreat": False, "CountryChecked": False}})
        # Check the packet against various criteria and flag if necessary
        pkt_checker(src, dst, proto, sport, dport, flags, size)
        # Store raw packet summary in the database
        packet_to_database(3, gen_id(src), src, proto=proto, sport=sport, dport=dport, size=size)

def pkt_checker(src, dst, proto, sport, dport, flags, size):
    global recent_ips
    # Check if the source IP is from a dangerous country
    if countries and not recent_ips[src]["CountryChecked"]:
        response = get_country(src)
        recent_ips[src]["CountryChecked"] = True
        if not response:
            pass
        else:
            if response in countries:
                print(f"Packet from {src} is from an unsafe country: {response}")
                packet_to_database(1, gen_id(src), src, risk=risk_weights['suspicious_country'])
                packet_to_database(2, gen_id(src), src, flag_reason=f"From {response}", source="GeoIP")
    # Check against abuseipdb database for reports of malicious activity
    if abuseipdb_key not in ('', 'your_abuseipdb_key') and not recent_ips[src]["AbuseIPDB"]:
        querystring = {
            'ipAddress': src,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': abuseipdb_key,
        }
        response = requests.request(method='GET', url='https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring)
        response = json.loads(response.text)
        recent_ips[src]["AbuseIPDB"] = True
        if response["data"]["totalReports"] > abuse_threshold:
            print(f"Packet from {src} has been reported {response['data']['totalReports']} times in the last 90 days")
            packet_to_database(1, gen_id(src), src, risk=risk_weights['abuseipdb'])
            packet_to_database(2, gen_id(src), src, flag_reason=f"{response['data']['totalReports']} reports", source="AbuseIPDB")
    # Check for repeated packets from the same IP
    if recent_ips[src]["count"] == threshold +1:
        print(f"Packet from {src} has been observed {recent_ips[src]['count']} times")
        packet_to_database(1, gen_id(src), src, risk=risk_weights['repeated_packets'])
        packet_to_database(2, gen_id(src), src, flag_reason=f"{recent_ips[src]['count']} packets observed", source="Internal Scans")
    # Check for common attack ports
    if dport in suspicious_ports:
        print(f"Packet from {src} is targeting a common attack port: {dport}")
        packet_to_database(1, gen_id(src), src, risk=risk_weights['suspicious_port'])
        packet_to_database(2, gen_id(src), src, flag_reason=f"Targeting port {dport}", source="Port Scanning")
    # Check against the ipthreat list
    if IPThreat_state and not recent_ips[src]["IPThreat"]:
        level = check_ipthreat(src)
        if level:
            print(f"Packet from {src} is in the IPThreat list with a threat score of {level}")
            packet_to_database(1, gen_id(src), src, risk=int(level))
            packet_to_database(2, gen_id(src), src, flag_reason=f"Listed in IPThreat with a score of {level}", source="IPThreat List")
            recent_ips[src]["IPThreat"] = True

# -------------- HELPER FUNCTIONS --------------
def get_country(ip):
    global recent_ips
    # Make the API call to ip-api.com
    try:
        url = f'http://ip-api.com/json/{ip}'
        response = requests.get(url, timeout=20)
        response.raise_for_status()

        data = response.json()
        if data.get('status') == 'success':
            country = data.get('country', 'Unknown')
        else:
            print(f"ip-api lookup failed for {ip}: {data.get('message', 'Unknown error')}")
            country = 'Unknown'

        recent_ips[ip]["CountryChecked"] = True
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
def download_ipthreat():
    # Download the IPThreat list from their website and turn it into a list
    try:
        url = 'https://lists.ipthreat.net/file/ipthreat-lists/threat/threat-1.txt'
        response = requests.get(url)
        response.raise_for_status()
        global IPThreat
        IPThreat = {}
        for line in response.text.splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            parts = line.split(' # ')
            if not parts:
                continue
            ip_or_range = parts[0].strip()
            threat = parts[1].split(' ')[0]
            if '-' in ip_or_range:
                IPThreat[ip_or_range] = threat
            else:
                try:
                    if '/' in ip_or_range:
                        IPThreat[ip_or_range] = threat
                    else:
                        IPThreat[ip_or_range] = threat
                except ValueError:
                    print(f"Skipping invalid entry: {ip_or_range}")
    except Exception as e:
        print(f"Error during IPThreat list download: {e}")      
def check_ipthreat(ip):
    # Check if the ip itself is in the list
    if ip in IPThreat:
        return IPThreat[ip]
    # If not maybe the range is in the list
    for entry, level in IPThreat.items():
        if '/' in entry:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                    return level
            except ValueError:
                continue
        elif '-' in entry:
            start, end = entry.split('-')
            try:
                if ipaddress.ip_address(start) <= ipaddress.ip_address(ip) <= ipaddress.ip_address(end):
                    return level
            except ValueError:
                continue
    return None     
def db_structure():
    global conn, c
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
def csv_export(data, name):
    if (input("Do you want to export to a csv file? (y/n): ") == 'y'):
                    with open(f'{name}.csv', 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerows(data)  

if __name__ == "__main__":
    main()