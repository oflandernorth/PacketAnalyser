# PacketAnalyser

A Python-based network traffic analysis tool that captures live packets or reads PCAP files, enriches source IPs with threat intelligence (AbuseIPDB, IPThreat, GeoIP), calculates dynamic risk scores, and stores structured results in a normalized SQLite database.

---

## Features

- **Live or offline capture** – Sniff traffic from a network interface or analyze a previously saved capture.
- **Multiple threat intelligence sources** – Query AbuseIPDB API for reputation, check IPs against the IPThreat blocklist, and flag high-risk countries.
- **Geographic risk** – Flag IPs from user-defined high-risk countries using ip-api.com (free, no API key required).
- **Port scanning detection** – Alert on connection attempts to commonly targeted ports (e.g., 22, 445, 3389).
- **Volume-based anomaly detection** – Flag IPs that exceed a configurable packet count threshold.
- **Safelist support** – Skip analysis for trusted IPs (e.g., internal monitoring, known good hosts).
- **Normalized database schema** – Three related tables: `ip_observations`, `suspicious_flags`, `raw_packet_summary`.
- **Risk score accumulation** – Each suspicious activity adds a configurable weight to the IP’s running risk total.
- **Post-capture analysis** – After capture, interactively query the database: view top suspicious IPs with flags, delete entries, or inspect a specific IP.
- **CSV export** – Export top 10 results (simple or with flags) to CSV files.
- **CLI mode** – Fully scriptable command‑line interface for live capture, PCAP reading, and database operations (see below).
- **Colour‑coded output** – Clear visual distinction between normal info (green) and alerts (orange).
- **Configurable via YAML** – No hardcoded values; adjust thresholds, API keys, risk weights, ports, and file paths easily.

---

## Project Structure

```
PacketAnalyser/
├── MonitorTool.py           # Main script (capture, analysis, DB, CLI)
├── config.yaml              # Configuration file
├── safelist.txt             # Optional: one IP per line to ignore
├── countries.txt            # Optional: high-risk country names (one per line)
├── PacketAnalyzer.db        # SQLite database (auto-created)
└── README.md
```

---

## Setup & Installation

### 1. Clone & Dependencies

```bash
git clone https://github.com/oflandernorth/PacketAnalyser.git
cd PacketAnalyser
pip install scapy requests pyyaml ipaddress
```

> **Note**: `scapy` may require administrator/root privileges to capture live traffic.

### 2. Obtain API Keys (Optional)

- **AbuseIPDB** – Sign up at [AbuseIPDB](https://www.abuseipdb.com/) for a free API key.

### 3. Configure `config.yaml`

```yaml
paths:
  safelist: "safelist.txt"          # leave empty to disable
  countries: "countries.txt"        # leave empty to disable
  database: "PacketAnalyzer.db"

data:
  abuseipdb: "your_abuseipdb_key"   # leave empty to disable API checks
  ipthreat: True                      # set to True to enable IPThreat list checking
  abuseipdb_threshold: 5            # min reports to flag as suspicious
  network_interface: "Wi-Fi"         # change to your interface ("Wi-Fi" on windows / "en0" on macOS)
  count_threshold: 10               # number of packets from same IP to trigger alert
  suspicious_ports: [22, 23, 445, 3389] # common ports for attacks (SSH, Telnet, SMB, RDP)

risk_weights:
  abuseipdb: 10 # weight for AbuseIPDB reports
  repeated_packets: 5 # weight for multiple packets from same IP
  suspicious_port: 20 # weight for packets targeting suspicious ports
  suspicious_country: 10 # weight for packets from high-risk countries
```

### 4. Prepare Optional Lists

- **safelist.txt** – one IP per line. Packets from these IPs are completely ignored.
- **countries.txt** – one country name per line (exactly as returned by the GeoIP API).  
  Example: `China`, `Russia`, `North Korea`.

---

## Usage

The tool supports two modes of operation: **interactive** (no arguments) and **CLI** (command‑line driven).

### Interactive Mode

Run the script without arguments:

```bash
python MonitorTool.py
```

Then follow the prompts.
When viewing top 10 results, you’ll be asked if you want to export them to a CSV file (the file is saved in the current directory as `Top10Sum.csv` or `Top10SumFlag.csv`).

### CLI Mode (Scriptable)

All functionality is available via command‑line arguments – ideal for automation or integration into larger workflows.

#### Live capture

```bash
# Capture for 60 seconds
python MonitorTool.py live --timeout 60

# Capture exactly 500 packets
python MonitorTool.py live --count 500
```

#### Read a PCAP file

```bash
python MonitorTool.py read capture.pcap
```

#### Database operations

```bash
# Show top 10 suspicious IPs (risk only)
python MonitorTool.py db top10

# Show top 10 with flags, and automatically export CSV (no prompt)
python MonitorTool.py db top10-flags --csv

# Clear all data (skip confirmation)
python MonitorTool.py db reset --yes

# Delete a specific IP
python MonitorTool.py db delete-ip 192.0.2.5

# View all observations for an IP
python MonitorTool.py db view-ip 203.0.113.10
```

Currently the CLI arguments cannot be used together for more functionality, and i do not know if i will implement it.

---

## Database Schema

The tool uses a normalized SQLite database with three tables:

### `ip_observations`
| Column     | Type    | Description                                 |
|------------|---------|---------------------------------------------|
| ID         | INTEGER | PRIMARY KEY (derived from IP using `ipaddress`) |
| IP         | TEXT    | Source IP address (string)                  |
| FSEEN      | TEXT    | First seen timestamp                        |
| LSEEN      | TEXT    | Last seen timestamp                         |
| RISK       | INTEGER | Accumulated risk score (higher = more suspicious) |

### `suspicious_flags`
| Column          | Type    | Description                                |
|-----------------|---------|--------------------------------------------|
| ID              | INTEGER | PRIMARY KEY AUTOINCREMENT                 |
| OBSERVATION_ID  | INTEGER | Foreign key to `ip_observations(ID)`      |
| FLAG_REASON     | TEXT    | Why it was flagged (e.g., "From China")    |
| SOURCE          | TEXT    | Source of flag (GeoIP, AbuseIPDB, IPThreat List, etc.) |

### `raw_packet_summary`
| Column          | Type    | Description                                |
|-----------------|---------|--------------------------------------------|
| ID              | INTEGER | PRIMARY KEY AUTOINCREMENT                 |
| OBSERVATION_ID  | INTEGER | Foreign key to `ip_observations(ID)`      |
| PROTOCOL        | TEXT    | Protocol number (6=TCP, 17=UDP)           |
| SRC_PORT        | INTEGER | Source port (if TCP/UDP)                  |
| DST_PORT        | INTEGER | Destination port (if TCP/UDP)             |
| PACKET_SIZE     | INTEGER | Size of packet payload in bytes           |

---

## Risk Scoring Logic

Each suspicious activity adds a configurable weight (from `risk_weights` in `config.yaml`) to the IP’s `RISK` score. Default weights:

| Condition                                      | Risk Added |
|------------------------------------------------|------------|
| IP from high-risk country (GeoIP)              | 10         |
| IP has > `abuseipdb_threshold` reports         | 10         |
| IP exceeds `count_threshold` packets in session| 5          |
| Destination port is in `suspicious_ports`      | 20         |
| IP found in IPThreat blocklist                 | varies*    |

\* The IPThreat list provides its own threat level (e.g., 3, 5, 10), which is added directly to the risk score.

You can modify all weights in `config.yaml`.

---

## Example Output

**Live capture alerts (coloured):**
```
Starting live capture
Packet from 185.130.5.253 is from an unsafe country: Russia
Packet from 185.130.5.253 has been reported 12 times in the last 90 days
Packet from 185.130.5.253 is targeting a common attack port: 445
Packet from 93.184.216.34 is in the IPThreat list with a threat score of 5
```

**Post‑capture query (option 2):**
```
IP: 185.130.5.253, Risk Score: 45, Flags: From Russia (Source: GeoIP); 12 reports (Source: AbuseIPDB); Targeting port 445 (Source: Port Scanning)
```

**CSV export** (example `Top10SumFlag.csv`):
```
IP,RISK,FLAGS
185.130.5.253,45,"From Russia (Source: GeoIP); 12 reports (Source: AbuseIPDB); Targeting port 445 (Source: Port Scanning)"
93.184.216.34,5,"Listed in IPThreat with a score of 5 (Source: IPThreat List)"
...
```

---

## TODO / Future Enhancements

The following features are planned or already implemented.  
✅ = done, 📝 = planned.

### High Priority

- ✅ **Implement `read_cap()` function** – analysis of existing PCAP files using `scapy`’s `PcapReader`.
- ✅ **Time-series reporting** – queries to show "Top 10 most suspicious IPs" and IPs with flags.
- ✅ **Human-readable report** – post‑capture interactive console menu.
- ✅ **Export to CSV** – save top 10 summaries to CSV files.
- ✅ **Configurable risk scoring** – weights in `config.yaml`.

### Medium Priority

- ✅ **Add other threat intel sources** – IPThreat list integration.
- ✅ **Command-line arguments** – `live`, `read`, `db` subcommands with options (`--timeout`, `--count`, `--csv`, `--yes`).
- 📝 **Asynchronous API queries** – prevent packet processing from blocking on slow HTTP requests.

### Low Priority / Stretch Goals

- 📝 **Basic web dashboard** (Flask + Chart.js) to visualize risk trends.
- 📝 **Docker support** – containerize with all dependencies.
- 📝 **Unit tests** – for risk calculation and database insertion logic.

---

## Troubleshooting

| Problem                                      | Solution                                                                 |
|----------------------------------------------|--------------------------------------------------------------------------|
| `Permission denied` when capturing           | Run with `sudo` (Linux/macOS) or as Administrator (Windows).             |
| AbuseIPDB returns 401                        | Check your API key in `config.yaml` – ensure it’s not empty or revoked. |
| GeoIP returns "Unknown" for all IPs          | ip-api.com has rate limits; wait a few seconds or use a VPN.             |
| `safelist` / `countries` not working         | Make sure the file paths are correct and each entry is on a new line.    |
| Database `ON CONFLICT` syntax error          | SQLite version must be ≥ 3.24.0. Upgrade if needed.                      |
| `scapy` not capturing on Wi-Fi (Windows)     | Install Npcap and use interface name like `"Wi-Fi"` (check with `show_interfaces()`). |
| IPThreat download fails                      | Check internet connection; the URL may change – update in `download_ipthreat()`. |

---

## Contributing

Pull requests are welcome! Please follow the existing code style and add docstrings for new functions. For major changes, open an issue first to discuss.

---

## License

MIT – free to use, modify, and distribute.

---

## Acknowledgments

- Built with [Scapy](https://scapy.net/)
- Threat intel: [AbuseIPDB](https://www.abuseipdb.com/), [IPThreat](https://ipthreat.net/)
- GeoIP: [ip-api.com](https://ip-api.com/)
- Inspired by SOC analyst workflows and the need for simple, transparent threat detection.

---

**Happy analyzing!**